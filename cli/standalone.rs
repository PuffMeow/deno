// Copyright 2018-2023 the Deno authors. All rights reserved. MIT license.

use crate::args::CaData;
use crate::args::Flags;
use crate::colors;
use crate::file_fetcher::get_source_from_data_url;
use crate::ops;
use crate::proc_state::ProcState;
use crate::util::v8::construct_v8_flags;
use crate::version;
use crate::CliGraphResolver;
use deno_core::anyhow::Context;
use deno_core::error::type_error;
use deno_core::error::AnyError;
use deno_core::futures::io::AllowStdIo;
use deno_core::futures::task::LocalFutureObj;
use deno_core::futures::AsyncReadExt;
use deno_core::futures::AsyncSeekExt;
use deno_core::futures::FutureExt;
use deno_core::located_script_name;
use deno_core::serde::Deserialize;
use deno_core::serde::Serialize;
use deno_core::serde_json;
use deno_core::url::Url;
use deno_core::v8_set_flags;
use deno_core::ModuleLoader;
use deno_core::ModuleSpecifier;
use deno_core::ResolutionKind;
use deno_graph::source::Resolver;
use deno_runtime::fmt_errors::format_js_error;
use deno_runtime::ops::worker_host::CreateWebWorkerCb;
use deno_runtime::ops::worker_host::WorkerEventCb;
use deno_runtime::permissions::Permissions;
use deno_runtime::permissions::PermissionsContainer;
use deno_runtime::permissions::PermissionsOptions;
use deno_runtime::web_worker::WebWorker;
use deno_runtime::web_worker::WebWorkerOptions;
use deno_runtime::worker::MainWorker;
use deno_runtime::worker::WorkerOptions;
use deno_runtime::BootstrapOptions;
use import_map::parse_from_json;
use log::Level;
use std::env::current_exe;
use std::io::SeekFrom;
use std::pin::Pin;
use std::rc::Rc;
use std::sync::Arc;

/// 元数据
#[derive(Deserialize, Serialize)]
pub struct Metadata {
  /// 收集到的命令行参数
  pub argv: Vec<String>,
  pub unstable: bool,
  pub seed: Option<u64>,
  /// 运行的权限
  pub permissions: PermissionsOptions,
  /// 文件位置
  pub location: Option<Url>,
  pub v8_flags: Vec<String>,
  pub log_level: Option<Level>,
  pub ca_stores: Option<Vec<String>>,
  pub ca_data: Option<Vec<u8>>,
  pub unsafely_ignore_certificate_errors: Option<Vec<String>>,
  pub maybe_import_map: Option<(Url, String)>,
  /// 主要入口模块
  pub entrypoint: ModuleSpecifier,
}

pub const MAGIC_TRAILER: &[u8; 8] = b"d3n0l4nd";

/// 输出:
/// 该函数将尝试作为由 deno compile 生成的独立二进制文件运行此二进制文件。
/// 它通过检查 EOF-24 处的魔术尾缀字符串 d3n0l4nd 来确定是否为独立二进制文件。
///
/// 魔术尾缀后面跟着：
/// - 嵌入在二进制文件中的 JS 捆绑包的 u64 指针
/// - 嵌入在二进制文件中的 JSON 元数据（序列化标志）的 u64 指针
/// 这些指针被解除引用，并在元数据指定的配置下执行捆绑包。如果不存在魔术尾缀，则该函数以 Ok(None) 退出。
pub async fn extract_standalone(
  args: Vec<String>,
) -> Result<Option<(Metadata, eszip::EszipV2)>, AnyError> {
  // 获得当前可执行命令行文件的完整路径
  let current_exe_path = current_exe()?;
  // 打开它
  let file = std::fs::File::open(current_exe_path)?;

  // 缓存读取器
  let mut bufreader =
    deno_core::futures::io::BufReader::new(AllowStdIo::new(file));

  // 取出尾缀来看看
  let trailer_pos = bufreader.seek(SeekFrom::End(-24)).await?;
  let mut trailer = [0; 24];
  // 读取尾缀
  bufreader.read_exact(&mut trailer).await?;
  // 魔法尾缀
  let (magic_trailer, rest) = trailer.split_at(8);
  // 如果不是魔法尾缀直接返回 None
  if magic_trailer != MAGIC_TRAILER {
    return Ok(None);
  }

  let (eszip_archive_pos, rest) = rest.split_at(8);
  let metadata_pos = rest;
  let eszip_archive_pos = u64_from_bytes(eszip_archive_pos)?;
  let metadata_pos = u64_from_bytes(metadata_pos)?;
  let metadata_len = trailer_pos - metadata_pos;

  bufreader.seek(SeekFrom::Start(eszip_archive_pos)).await?;

  // eszip 可以下载JavaScript和TypeScript模块图，并将它们存储在本地一个特殊的zip文件中
  // 返回的 eszip 包含了模块图信息
  let (eszip, loader) = eszip::EszipV2::parse(bufreader)
    .await
    .context("Failed to parse eszip header")?;

  let mut bufreader = loader.await.context("Failed to parse eszip archive")?;

  bufreader.seek(SeekFrom::Start(metadata_pos)).await?;

  let mut metadata = String::new();

  // 读取模块图中的元数据信息
  bufreader
    .take(metadata_len)
    .read_to_string(&mut metadata)
    .await
    .context("Failed to read metadata from the current executable")?;

  // json parse 成 Metadata 对象
  let mut metadata: Metadata = serde_json::from_str(&metadata).unwrap();
  // 命令行参数放到元数据中
  metadata.argv.append(&mut args[1..].to_vec());

  // 返回元数据和 eszip 模块图信息
  Ok(Some((metadata, eszip)))
}

fn u64_from_bytes(arr: &[u8]) -> Result<u64, AnyError> {
  let fixed_arr: &[u8; 8] = arr
    .try_into()
    .context("Failed to convert the buffer into a fixed-size array")?;
  Ok(u64::from_be_bytes(*fixed_arr))
}

#[derive(Clone)]
struct EmbeddedModuleLoader {
  eszip: Arc<eszip::EszipV2>,
  maybe_import_map_resolver: Option<Arc<CliGraphResolver>>,
}

impl ModuleLoader for EmbeddedModuleLoader {
  fn resolve(
    &self,
    specifier: &str,
    referrer: &str,
    _kind: ResolutionKind,
  ) -> Result<ModuleSpecifier, AnyError> {
    // Try to follow redirects when resolving.
    let referrer = match self.eszip.get_module(referrer) {
      Some(eszip::Module { ref specifier, .. }) => {
        ModuleSpecifier::parse(specifier)?
      }
      None => {
        let cwd = std::env::current_dir().context("Unable to get CWD")?;
        deno_core::resolve_url_or_path(referrer, &cwd)?
      }
    };

    self
      .maybe_import_map_resolver
      .as_ref()
      .map(|r| r.resolve(specifier, &referrer))
      .unwrap_or_else(|| {
        deno_core::resolve_import(specifier, referrer.as_str())
          .map_err(|err| err.into())
      })
  }

  fn load(
    &self,
    module_specifier: &ModuleSpecifier,
    _maybe_referrer: Option<ModuleSpecifier>,
    _is_dynamic: bool,
  ) -> Pin<Box<deno_core::ModuleSourceFuture>> {
    let is_data_uri = get_source_from_data_url(module_specifier).ok();
    let module = self
      .eszip
      .get_module(module_specifier.as_str())
      .ok_or_else(|| type_error("Module not found"));

    let module_specifier = module_specifier.clone();
    async move {
      if let Some((source, _)) = is_data_uri {
        return Ok(deno_core::ModuleSource {
          code: source.into_bytes().into_boxed_slice(),
          module_type: deno_core::ModuleType::JavaScript,
          module_url_specified: module_specifier.to_string(),
          module_url_found: module_specifier.to_string(),
        });
      }

      let module = module?;
      let code = module.source().await;
      let code = std::str::from_utf8(&code)
        .map_err(|_| type_error("Module source is not utf-8"))?
        .to_owned();

      Ok(deno_core::ModuleSource {
        code: code.into_bytes().into_boxed_slice(),
        module_type: match module.kind {
          eszip::ModuleKind::JavaScript => deno_core::ModuleType::JavaScript,
          eszip::ModuleKind::Json => deno_core::ModuleType::Json,
        },
        module_url_specified: module_specifier.to_string(),
        module_url_found: module_specifier.to_string(),
      })
    }
    .boxed_local()
  }
}

fn metadata_to_flags(metadata: &Metadata) -> Flags {
  let permissions = metadata.permissions.clone();
  Flags {
    argv: metadata.argv.clone(),
    unstable: metadata.unstable,
    seed: metadata.seed,
    location: metadata.location.clone(),
    allow_env: permissions.allow_env,
    allow_hrtime: permissions.allow_hrtime,
    allow_net: permissions.allow_net,
    allow_ffi: permissions.allow_ffi,
    allow_read: permissions.allow_read,
    allow_run: permissions.allow_run,
    allow_write: permissions.allow_write,
    v8_flags: metadata.v8_flags.clone(),
    log_level: metadata.log_level,
    ca_stores: metadata.ca_stores.clone(),
    ca_data: metadata.ca_data.clone().map(CaData::Bytes),
    ..Default::default()
  }
}

fn web_worker_callback() -> Arc<WorkerEventCb> {
  Arc::new(|worker| {
    let fut = async move { Ok(worker) };
    LocalFutureObj::new(Box::new(fut))
  })
}

fn create_web_worker_callback(
  ps: &ProcState,
  module_loader: &Rc<EmbeddedModuleLoader>,
) -> Arc<CreateWebWorkerCb> {
  let ps = ps.clone();
  let module_loader = module_loader.as_ref().clone();
  Arc::new(move |args| {
    let module_loader = Rc::new(module_loader.clone());

    let create_web_worker_cb = create_web_worker_callback(&ps, &module_loader);
    let web_worker_cb = web_worker_callback();

    let options = WebWorkerOptions {
      bootstrap: BootstrapOptions {
        args: ps.options.argv().clone(),
        cpu_count: std::thread::available_parallelism()
          .map(|p| p.get())
          .unwrap_or(1),
        debug_flag: ps.options.log_level().map_or(false, |l| l == Level::Debug),
        enable_testing_features: false,
        locale: deno_core::v8::icu::get_language_tag(),
        location: Some(args.main_module.clone()),
        no_color: !colors::use_color(),
        is_tty: colors::is_tty(),
        runtime_version: version::deno(),
        ts_version: version::TYPESCRIPT.to_string(),
        unstable: ps.options.unstable(),
        user_agent: version::get_user_agent(),
        inspect: ps.options.is_inspecting(),
      },
      extensions: ops::cli_exts(ps.clone()),
      startup_snapshot: Some(crate::js::deno_isolate_init()),
      unsafely_ignore_certificate_errors: ps
        .options
        .unsafely_ignore_certificate_errors()
        .clone(),
      root_cert_store: Some(ps.root_cert_store.clone()),
      seed: ps.options.seed(),
      module_loader,
      npm_resolver: None, // not currently supported
      create_web_worker_cb,
      preload_module_cb: web_worker_cb.clone(),
      pre_execute_module_cb: web_worker_cb,
      format_js_error_fn: Some(Arc::new(format_js_error)),
      source_map_getter: None,
      worker_type: args.worker_type,
      maybe_inspector_server: None,
      get_error_class_fn: Some(&get_error_class_name),
      blob_store: ps.blob_store.clone(),
      broadcast_channel: ps.broadcast_channel.clone(),
      shared_array_buffer_store: Some(ps.shared_array_buffer_store.clone()),
      compiled_wasm_module_store: Some(ps.compiled_wasm_module_store.clone()),
      cache_storage_dir: None,
      stdio: Default::default(),
    };

    WebWorker::bootstrap_from_options(
      args.name,
      args.permissions,
      args.main_module,
      args.worker_id,
      options,
    )
  })
}

pub async fn run(
  eszip: eszip::EszipV2,
  metadata: Metadata,
) -> Result<(), AnyError> {
  // metadata 转成 flag 用户输入的权限参数
  let flags = metadata_to_flags(&metadata);
  // 主要运行模块的入口
  let main_module = &metadata.entrypoint;
  // 获取共享的程序运行状态
  let ps = ProcState::build(flags).await?;
  // 处理运行权限
  let permissions = PermissionsContainer::new(Permissions::from_options(
    &metadata.permissions,
  )?);
  // 内嵌模块加载器
  let module_loader = Rc::new(EmbeddedModuleLoader {
    eszip: Arc::new(eszip),
    maybe_import_map_resolver: metadata.maybe_import_map.map(
      |(base, source)| {
        Arc::new(CliGraphResolver::new(
          None,
          Some(Arc::new(
            parse_from_json(&base, &source).unwrap().import_map,
          )),
          false,
          ps.npm_api.clone(),
          ps.npm_resolution.clone(),
          ps.package_json_deps_installer.clone(),
        ))
      },
    ),
  });
  let create_web_worker_cb = create_web_worker_callback(&ps, &module_loader);
  let web_worker_cb = web_worker_callback();

  v8_set_flags(construct_v8_flags(&metadata.v8_flags, vec![]));

  let options = WorkerOptions {
    bootstrap: BootstrapOptions {
      args: metadata.argv,
      cpu_count: std::thread::available_parallelism()
        .map(|p| p.get())
        .unwrap_or(1),
      debug_flag: metadata
        .log_level
        .map(|l| l == Level::Debug)
        .unwrap_or(false),
      enable_testing_features: false,
      locale: deno_core::v8::icu::get_language_tag(),
      location: metadata.location,
      no_color: !colors::use_color(),
      is_tty: colors::is_tty(),
      runtime_version: version::deno(),
      ts_version: version::TYPESCRIPT.to_string(),
      unstable: metadata.unstable,
      user_agent: version::get_user_agent(),
      inspect: ps.options.is_inspecting(),
    },
    extensions: ops::cli_exts(ps.clone()),
    startup_snapshot: Some(crate::js::deno_isolate_init()),
    unsafely_ignore_certificate_errors: metadata
      .unsafely_ignore_certificate_errors,
    root_cert_store: Some(ps.root_cert_store.clone()),
    seed: metadata.seed,
    source_map_getter: None,
    format_js_error_fn: Some(Arc::new(format_js_error)),
    create_web_worker_cb,
    web_worker_preload_module_cb: web_worker_cb.clone(),
    web_worker_pre_execute_module_cb: web_worker_cb,
    maybe_inspector_server: None,
    should_break_on_first_statement: false,
    should_wait_for_inspector_session: false,
    module_loader,
    npm_resolver: None, // not currently supported
    get_error_class_fn: Some(&get_error_class_name),
    cache_storage_dir: None,
    origin_storage_dir: None,
    blob_store: ps.blob_store.clone(),
    broadcast_channel: ps.broadcast_channel.clone(),
    shared_array_buffer_store: Some(ps.shared_array_buffer_store.clone()),
    compiled_wasm_module_store: Some(ps.compiled_wasm_module_store.clone()),
    stdio: Default::default(),
  };
  let mut worker = MainWorker::bootstrap_from_options(
    main_module.clone(),
    permissions,
    options,
  );
  worker.execute_main_module(main_module).await?;
  worker.dispatch_load_event(&located_script_name!())?;

  loop {
    worker.run_event_loop(false).await?;
    if !worker.dispatch_beforeunload_event(&located_script_name!())? {
      break;
    }
  }

  worker.dispatch_unload_event(&located_script_name!())?;
  std::process::exit(0);
}

fn get_error_class_name(e: &AnyError) -> &'static str {
  deno_runtime::errors::get_error_class_name(e).unwrap_or_else(|| {
    panic!(
      "Error '{}' contains boxed error of unsupported type:{}",
      e,
      e.chain().map(|e| format!("\n  {e:?}")).collect::<String>()
    );
  })
}
