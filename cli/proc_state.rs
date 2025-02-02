// Copyright 2018-2023 the Deno authors. All rights reserved. MIT license.

use crate::args::CliOptions;
use crate::args::DenoSubcommand;
use crate::args::Flags;
use crate::args::Lockfile;
use crate::args::StorageKeyResolver;
use crate::args::TsConfigType;
use crate::cache::Caches;
use crate::cache::DenoDir;
use crate::cache::EmitCache;
use crate::cache::HttpCache;
use crate::cache::NodeAnalysisCache;
use crate::cache::ParsedSourceCache;
use crate::emit::Emitter;
use crate::file_fetcher::FileFetcher;
use crate::graph_util::ModuleGraphBuilder;
use crate::graph_util::ModuleGraphContainer;
use crate::http_util::HttpClient;
use crate::module_loader::CliModuleLoaderFactory;
use crate::module_loader::ModuleLoadPreparer;
use crate::module_loader::NpmModuleLoader;
use crate::node::CliCjsEsmCodeAnalyzer;
use crate::node::CliNodeCodeTranslator;
use crate::npm::create_npm_fs_resolver;
use crate::npm::CliNpmRegistryApi;
use crate::npm::CliNpmResolver;
use crate::npm::NpmCache;
use crate::npm::NpmResolution;
use crate::npm::PackageJsonDepsInstaller;
use crate::resolver::CliGraphResolver;
use crate::tools::check::TypeChecker;
use crate::util::progress_bar::ProgressBar;
use crate::util::progress_bar::ProgressBarStyle;
use crate::worker::CliMainWorkerFactory;
use crate::worker::CliMainWorkerOptions;

use deno_core::error::AnyError;
use deno_core::parking_lot::Mutex;
use deno_core::ModuleSpecifier;

use deno_runtime::deno_node;
use deno_runtime::deno_node::analyze::NodeCodeTranslator;
use deno_runtime::deno_node::NodeResolver;
use deno_runtime::deno_tls::rustls::RootCertStore;
use deno_runtime::deno_web::BlobStore;
use deno_runtime::inspector_server::InspectorServer;
use deno_semver::npm::NpmPackageReqReference;
use import_map::ImportMap;
use log::warn;
use std::collections::HashSet;
use std::ops::Deref;
use std::path::PathBuf;
use std::sync::Arc;

/// This structure represents state of single "deno" program.
///
/// It is shared by all created workers (thus V8 isolates).
/// 这个结构体用于存储一个 deno 实例的状态
/// 它的状态会被所有已经创建的 worker 共享
#[derive(Clone)]
pub struct ProcState(Arc<Inner>);

pub struct Inner {
  pub dir: DenoDir,
  pub caches: Arc<Caches>,
  pub file_fetcher: Arc<FileFetcher>,
  pub http_client: HttpClient,
  pub options: Arc<CliOptions>,
  pub emit_cache: EmitCache,
  pub emitter: Arc<Emitter>,
  pub graph_container: Arc<ModuleGraphContainer>,
  pub lockfile: Option<Arc<Mutex<Lockfile>>>,
  pub maybe_import_map: Option<Arc<ImportMap>>,
  pub maybe_inspector_server: Option<Arc<InspectorServer>>,
  pub root_cert_store: RootCertStore,
  pub blob_store: BlobStore,
  pub parsed_source_cache: Arc<ParsedSourceCache>,
  pub resolver: Arc<CliGraphResolver>,
  maybe_file_watcher_reporter: Option<FileWatcherReporter>,
  pub module_graph_builder: Arc<ModuleGraphBuilder>,
  pub module_load_preparer: Arc<ModuleLoadPreparer>,
  pub node_code_translator: Arc<CliNodeCodeTranslator>,
  pub node_fs: Arc<dyn deno_node::NodeFs>,
  pub node_resolver: Arc<NodeResolver>,
  pub npm_api: Arc<CliNpmRegistryApi>,
  pub npm_cache: Arc<NpmCache>,
  pub npm_resolver: Arc<CliNpmResolver>,
  pub npm_resolution: Arc<NpmResolution>,
  pub package_json_deps_installer: Arc<PackageJsonDepsInstaller>,
  pub cjs_resolutions: Arc<CjsResolutionStore>,
  progress_bar: ProgressBar,
}

impl Deref for ProcState {
  type Target = Arc<Inner>;
  fn deref(&self) -> &Self::Target {
    &self.0
  }
}

impl ProcState {
  pub async fn from_cli_options(
    options: Arc<CliOptions>,
  ) -> Result<Self, AnyError> {
    Self::build_with_sender(options, None).await
  }

  pub async fn from_flags(flags: Flags) -> Result<Self, AnyError> {
    Self::from_cli_options(Arc::new(CliOptions::from_flags(flags)?)).await
  }

  pub async fn from_flags_for_file_watcher(
    flags: Flags,
    files_to_watch_sender: tokio::sync::mpsc::UnboundedSender<Vec<PathBuf>>,
  ) -> Result<Self, AnyError> {
    // resolve the config each time
    let cli_options = Arc::new(CliOptions::from_flags(flags)?);
    let ps =
      Self::build_with_sender(cli_options, Some(files_to_watch_sender.clone()))
        .await?;
    ps.init_watcher();
    Ok(ps)
  }

  /// Reset all runtime state to its default. This should be used on file
  /// watcher restarts.
  pub fn reset_for_file_watcher(&mut self) {
    self.cjs_resolutions.clear();
    self.parsed_source_cache.clear();
    self.graph_container.clear();

    self.0 = Arc::new(Inner {
      dir: self.dir.clone(),
      caches: self.caches.clone(),
      options: self.options.clone(),
      emit_cache: self.emit_cache.clone(),
      emitter: self.emitter.clone(),
      file_fetcher: self.file_fetcher.clone(),
      http_client: self.http_client.clone(),
      graph_container: self.graph_container.clone(),
      lockfile: self.lockfile.clone(),
      maybe_import_map: self.maybe_import_map.clone(),
      maybe_inspector_server: self.maybe_inspector_server.clone(),
      root_cert_store: self.root_cert_store.clone(),
      blob_store: self.blob_store.clone(),
      parsed_source_cache: self.parsed_source_cache.clone(),
      resolver: self.resolver.clone(),
      maybe_file_watcher_reporter: self.maybe_file_watcher_reporter.clone(),
      module_graph_builder: self.module_graph_builder.clone(),
      module_load_preparer: self.module_load_preparer.clone(),
      node_code_translator: self.node_code_translator.clone(),
      node_fs: self.node_fs.clone(),
      node_resolver: self.node_resolver.clone(),
      npm_api: self.npm_api.clone(),
      npm_cache: self.npm_cache.clone(),
      npm_resolver: self.npm_resolver.clone(),
      npm_resolution: self.npm_resolution.clone(),
      package_json_deps_installer: self.package_json_deps_installer.clone(),
      cjs_resolutions: self.cjs_resolutions.clone(),
      progress_bar: self.progress_bar.clone(),
    });
    self.init_watcher();
  }

  // Add invariant files like the import map and explicit watch flag list to
  // the watcher. Dedup for build_for_file_watcher and reset_for_file_watcher.
  fn init_watcher(&self) {
    let files_to_watch_sender = match &self.0.maybe_file_watcher_reporter {
      Some(reporter) => &reporter.sender,
      None => return,
    };
    if let Some(watch_paths) = self.options.watch_paths() {
      files_to_watch_sender.send(watch_paths.clone()).unwrap();
    }
    if let Ok(Some(import_map_path)) = self
      .options
      .resolve_import_map_specifier()
      .map(|ms| ms.and_then(|ref s| s.to_file_path().ok()))
    {
      files_to_watch_sender.send(vec![import_map_path]).unwrap();
    }
  }

  async fn build_with_sender(
    cli_options: Arc<CliOptions>,
    maybe_sender: Option<tokio::sync::mpsc::UnboundedSender<Vec<PathBuf>>>,
  ) -> Result<Self, AnyError> {
    let dir = cli_options.resolve_deno_dir()?;
    let caches = Arc::new(Caches::default());
    // 根据 CLI 模式预热知道的可能需要的缓存 
    // Warm up the caches we know we'll likely need based on the CLI mode
    match cli_options.sub_command() {
      DenoSubcommand::Run(_) => {
        _ = caches.dep_analysis_db(&dir);
        _ = caches.node_analysis_db(&dir);
      }
      DenoSubcommand::Check(_) => {
        _ = caches.dep_analysis_db(&dir);
        _ = caches.node_analysis_db(&dir);
        _ = caches.type_checking_cache_db(&dir);
      }
      _ => {}
    }

    // 用于存储二进制数据，具有内部可变性
    let blob_store = BlobStore::default();
    let deps_cache_location = dir.deps_folder_path();
    // 网络依赖缓存
    let http_cache = HttpCache::new(&deps_cache_location);
    // TLS 根证书存储区
    let root_cert_store = cli_options.resolve_root_cert_store()?;
    // 缓存文件的配置，默认用于本地模块
    let cache_usage = cli_options.cache_setting();
    // 处理网络的进度条
    let progress_bar = ProgressBar::new(ProgressBarStyle::TextOnly);

    // reqwest 请求客户端实例
    // 比如 deno run https://deno.land/std@0.183.0/examples/welcome.ts 就会调用网络请求
    let http_client = HttpClient::new(
      Some(root_cert_store.clone()),
      cli_options.unsafely_ignore_certificate_errors().clone(),
    )?;

    // 用于获取文件
    let file_fetcher = FileFetcher::new(
      http_cache,
      cache_usage,
      !cli_options.no_remote(),
      http_client.clone(),
      blob_store.clone(),
      Some(progress_bar.clone()),
    );

    // 锁文件
    let lockfile = cli_options.maybe_lock_file();
    // npm 仓库源地址，默认 https://registry.npmjs.org
    let npm_registry_url = CliNpmRegistryApi::default_url().to_owned();
    // npm 缓存配置
    let npm_cache = Arc::new(NpmCache::new(
      dir.npm_folder_path(),
      cli_options.cache_setting(),
      http_client.clone(),
      progress_bar.clone(),
    ));

    // npm 包的一些相关操作 api，比如获取包的信息，获取 npm 的 url 等
    let npm_api = Arc::new(CliNpmRegistryApi::new(
      npm_registry_url.clone(),
      npm_cache.clone(),
      http_client.clone(),
      progress_bar.clone(),
    ));

    // 处理 npm 锁文件的快照
    let npm_snapshot = cli_options
      .resolve_npm_resolution_snapshot(&npm_api)
      .await?;

    // npm 解析
    let npm_resolution = Arc::new(NpmResolution::from_serialized(
      npm_api.clone(),
      npm_snapshot,
      lockfile.as_ref().cloned(),
    ));
    let node_fs = Arc::new(deno_node::RealFs);

    // 创建 npm 文件处理器
    let npm_fs_resolver = create_npm_fs_resolver(
      node_fs.clone(),
      npm_cache.clone(),
      &progress_bar,
      npm_registry_url,
      npm_resolution.clone(),
      cli_options.node_modules_dir_path(),
    );

    // npm 处理
    let npm_resolver = Arc::new(CliNpmResolver::new(
      npm_resolution.clone(),
      npm_fs_resolver,
      lockfile.as_ref().cloned(),
    ));

    // package.json 依赖下载
    let package_json_deps_installer = Arc::new(PackageJsonDepsInstaller::new(
      npm_api.clone(),
      npm_resolution.clone(),
      cli_options.maybe_package_json_deps(),
    ));

    // import 的映射
    let maybe_import_map = cli_options
      .resolve_import_map(&file_fetcher)
      .await?
      .map(Arc::new);
    // 是否开启了检测服务器，内部会创建一个异步 socket 服务，可以用来进行 debug
    let maybe_inspector_server =
      cli_options.resolve_inspector_server().map(Arc::new);

    let resolver = Arc::new(CliGraphResolver::new(
      cli_options.to_maybe_jsx_import_source_config(),
      maybe_import_map.clone(),
      cli_options.no_npm(),
      npm_api.clone(),
      npm_resolution.clone(),
      package_json_deps_installer.clone(),
    ));

    let maybe_file_watcher_reporter =
      maybe_sender.map(|sender| FileWatcherReporter {
        sender,
        file_paths: Arc::new(Mutex::new(vec![])),
      });

    // ts 配置信息
    let ts_config_result =
      cli_options.resolve_ts_config_for_emit(TsConfigType::Emit)?;
    if let Some(ignored_options) = ts_config_result.maybe_ignored_options {
      warn!("{}", ignored_options);
    }
    // ts emit 缓存
    let emit_cache = EmitCache::new(dir.gen_cache.clone());
    // 解析后的源码缓存
    let parsed_source_cache =
      Arc::new(ParsedSourceCache::new(caches.dep_analysis_db(&dir)));
    let emit_options: deno_ast::EmitOptions = ts_config_result.ts_config.into();
    // ts emitter
    let emitter = Arc::new(Emitter::new(
      emit_cache.clone(),
      parsed_source_cache.clone(),
      emit_options,
    ));
    // npm 缓存
    let file_fetcher = Arc::new(file_fetcher);
    // node 分析缓存
    let node_analysis_cache =
      NodeAnalysisCache::new(caches.node_analysis_db(&dir));
    let cjs_esm_analyzer = CliCjsEsmCodeAnalyzer::new(node_analysis_cache);
    let node_resolver =
      Arc::new(NodeResolver::new(node_fs.clone(), npm_resolver.clone()));
    // 翻译 node 代码
    let node_code_translator = Arc::new(NodeCodeTranslator::new(
      cjs_esm_analyzer,
      node_fs.clone(),
      node_resolver.clone(),
      npm_resolver.clone(),
    ));
    // node 处理器
    // 类型检查
    let type_checker = Arc::new(TypeChecker::new(
      dir.clone(),
      caches.clone(),
      cli_options.clone(),
      node_resolver.clone(),
      npm_resolver.clone(),
    ));
    // 创建模块的 graph，记录各个模块之间的关系
    let module_graph_builder = Arc::new(ModuleGraphBuilder::new(
      cli_options.clone(),
      resolver.clone(),
      npm_resolver.clone(),
      parsed_source_cache.clone(),
      lockfile.clone(),
      emit_cache.clone(),
      file_fetcher.clone(),
      type_checker.clone(),
    ));
    // 模块依赖图容器
    let graph_container: Arc<ModuleGraphContainer> = Default::default();
    // 准备模块加载
    let module_load_preparer = Arc::new(ModuleLoadPreparer::new(
      cli_options.clone(),
      graph_container.clone(),
      lockfile.clone(),
      maybe_file_watcher_reporter.clone(),
      module_graph_builder.clone(),
      parsed_source_cache.clone(),
      progress_bar.clone(),
      resolver.clone(),
      type_checker,
    ));

    Ok(ProcState(Arc::new(Inner {
      dir,
      caches,
      options: cli_options,
      emit_cache,
      emitter,
      file_fetcher,
      http_client,
      graph_container,
      lockfile,
      maybe_import_map,
      maybe_inspector_server,
      root_cert_store,
      blob_store,
      parsed_source_cache,
      resolver,
      maybe_file_watcher_reporter,
      module_graph_builder,
      node_code_translator,
      node_fs,
      node_resolver,
      npm_api,
      npm_cache,
      npm_resolver,
      npm_resolution,
      package_json_deps_installer,
      cjs_resolutions: Default::default(),
      module_load_preparer,
      progress_bar,
    })))
  }

  // todo(dsherret): this is a transitory method as we separate out
  // ProcState from more code
  pub fn into_cli_main_worker_factory(self) -> CliMainWorkerFactory {
    CliMainWorkerFactory::new(
      StorageKeyResolver::from_options(&self.options),
      self.npm_resolver.clone(),
      self.node_resolver.clone(),
      self.graph_container.clone(),
      self.blob_store.clone(),
      CliModuleLoaderFactory::new(
        &self.options,
        self.emitter.clone(),
        self.graph_container.clone(),
        self.module_load_preparer.clone(),
        self.parsed_source_cache.clone(),
        self.resolver.clone(),
        NpmModuleLoader::new(
          self.cjs_resolutions.clone(),
          self.node_code_translator.clone(),
          self.node_resolver.clone(),
        ),
      ),
      self.root_cert_store.clone(),
      self.node_fs.clone(),
      self.maybe_inspector_server.clone(),
      CliMainWorkerOptions {
        argv: self.options.argv().clone(),
        debug: self
          .options
          .log_level()
          .map(|l| l == log::Level::Debug)
          .unwrap_or(false),
        coverage_dir: self.options.coverage_dir(),
        enable_testing_features: self.options.enable_testing_features(),
        has_node_modules_dir: self.options.has_node_modules_dir(),
        inspect_brk: self.options.inspect_brk().is_some(),
        inspect_wait: self.options.inspect_wait().is_some(),
        is_inspecting: self.options.is_inspecting(),
        is_npm_main: self.options.is_npm_main(),
        location: self.options.location_flag().clone(),
        maybe_binary_npm_command_name: {
          let mut maybe_binary_command_name = None;
          if let DenoSubcommand::Run(flags) = self.options.sub_command() {
            if let Ok(pkg_ref) = NpmPackageReqReference::from_str(&flags.script)
            {
              // if the user ran a binary command, we'll need to set process.argv[0]
              // to be the name of the binary command instead of deno
              let binary_name = pkg_ref
                .sub_path
                .as_deref()
                .unwrap_or(pkg_ref.req.name.as_str());
              maybe_binary_command_name = Some(binary_name.to_string());
            }
          }
          maybe_binary_command_name
        },
        origin_data_folder_path: self.dir.origin_data_folder_path(),
        seed: self.options.seed(),
        unsafely_ignore_certificate_errors: self
          .options
          .unsafely_ignore_certificate_errors()
          .clone(),
        unstable: self.options.unstable(),
      },
    )
  }
}

/// Keeps track of what module specifiers were resolved as CJS.
#[derive(Default)]
pub struct CjsResolutionStore(Mutex<HashSet<ModuleSpecifier>>);

impl CjsResolutionStore {
  pub fn clear(&self) {
    self.0.lock().clear();
  }

  pub fn contains(&self, specifier: &ModuleSpecifier) -> bool {
    self.0.lock().contains(specifier)
  }

  pub fn insert(&self, specifier: ModuleSpecifier) {
    self.0.lock().insert(specifier);
  }
}

#[derive(Clone, Debug)]
pub struct FileWatcherReporter {
  sender: tokio::sync::mpsc::UnboundedSender<Vec<PathBuf>>,
  file_paths: Arc<Mutex<Vec<PathBuf>>>,
}

impl deno_graph::source::Reporter for FileWatcherReporter {
  fn on_load(
    &self,
    specifier: &ModuleSpecifier,
    modules_done: usize,
    modules_total: usize,
  ) {
    let mut file_paths = self.file_paths.lock();
    if specifier.scheme() == "file" {
      file_paths.push(specifier.to_file_path().unwrap());
    }

    if modules_done == modules_total {
      self.sender.send(file_paths.drain(..).collect()).unwrap();
    }
  }
}
