// Copyright 2018-2023 the Deno authors. All rights reserved. MIT license.

use std::path::PathBuf;
use std::rc::Rc;
use std::sync::Arc;

use deno_ast::ModuleSpecifier;
use deno_core::error::AnyError;
use deno_core::futures::task::LocalFutureObj;
use deno_core::futures::FutureExt;
use deno_core::located_script_name;
use deno_core::url::Url;
use deno_core::CompiledWasmModuleStore;
use deno_core::Extension;
use deno_core::ModuleId;
use deno_core::SharedArrayBufferStore;
use deno_runtime::colors;
use deno_runtime::deno_broadcast_channel::InMemoryBroadcastChannel;
use deno_runtime::deno_node;
use deno_runtime::deno_node::NodeResolution;
use deno_runtime::deno_node::NodeResolver;
use deno_runtime::deno_tls::rustls::RootCertStore;
use deno_runtime::deno_web::BlobStore;
use deno_runtime::fmt_errors::format_js_error;
use deno_runtime::inspector_server::InspectorServer;
use deno_runtime::ops::worker_host::CreateWebWorkerCb;
use deno_runtime::ops::worker_host::WorkerEventCb;
use deno_runtime::permissions::PermissionsContainer;
use deno_runtime::web_worker::WebWorker;
use deno_runtime::web_worker::WebWorkerOptions;
use deno_runtime::worker::MainWorker;
use deno_runtime::worker::WorkerOptions;
use deno_runtime::BootstrapOptions;
use deno_semver::npm::NpmPackageReqReference;

use crate::args::StorageKeyResolver;
use crate::errors;
use crate::graph_util::ModuleGraphContainer;
use crate::module_loader::CliModuleLoaderFactory;
use crate::npm::CliNpmResolver;
use crate::ops;
use crate::tools;
use crate::tools::coverage::CoverageCollector;
use crate::util::checksum;
use crate::version;

pub struct CliMainWorkerOptions {
  pub argv: Vec<String>,
  pub debug: bool,
  pub coverage_dir: Option<String>,
  pub enable_testing_features: bool,
  pub has_node_modules_dir: bool,
  pub inspect_brk: bool,
  pub inspect_wait: bool,
  pub is_inspecting: bool,
  pub is_npm_main: bool,
  pub location: Option<Url>,
  pub maybe_binary_npm_command_name: Option<String>,
  pub origin_data_folder_path: PathBuf,
  pub seed: Option<u64>,
  pub unsafely_ignore_certificate_errors: Option<Vec<String>>,
  pub unstable: bool,
}

struct SharedWorkerState {
  pub options: CliMainWorkerOptions,
  pub storage_key_resolver: StorageKeyResolver,
  pub npm_resolver: Arc<CliNpmResolver>,
  pub node_resolver: Arc<NodeResolver>,
  pub graph_container: Arc<ModuleGraphContainer>,
  pub blob_store: BlobStore,
  pub broadcast_channel: InMemoryBroadcastChannel,
  pub shared_array_buffer_store: SharedArrayBufferStore,
  pub compiled_wasm_module_store: CompiledWasmModuleStore,
  pub module_loader_factory: CliModuleLoaderFactory,
  pub root_cert_store: RootCertStore,
  pub node_fs: Arc<dyn deno_node::NodeFs>,
  pub maybe_inspector_server: Option<Arc<InspectorServer>>,
}

pub struct CliMainWorker {
  main_module: ModuleSpecifier,
  is_main_cjs: bool,
  worker: MainWorker,
  shared: Arc<SharedWorkerState>,
}

impl CliMainWorker {
  pub fn into_main_worker(self) -> MainWorker {
    self.worker
  }

  pub async fn setup_repl(&mut self) -> Result<(), AnyError> {
    self.worker.run_event_loop(false).await?;
    Ok(())
  }

  pub async fn run(&mut self) -> Result<i32, AnyError> {
    let mut maybe_coverage_collector =
      self.maybe_setup_coverage_collector().await?;
    log::debug!("main_module {}", self.main_module);

    if self.is_main_cjs {
      self.initialize_main_module_for_node()?;
      deno_node::load_cjs_module(
        &mut self.worker.js_runtime,
        &self.main_module.to_file_path().unwrap().to_string_lossy(),
        true,
        self.shared.options.inspect_brk,
      )?;
    } else {
      self.execute_main_module_possibly_with_npm().await?;
    }

    self.worker.dispatch_load_event(located_script_name!())?;

    loop {
      self
        .worker
        .run_event_loop(maybe_coverage_collector.is_none())
        .await?;
      if !self
        .worker
        .dispatch_beforeunload_event(located_script_name!())?
      {
        break;
      }
    }

    self.worker.dispatch_unload_event(located_script_name!())?;

    if let Some(coverage_collector) = maybe_coverage_collector.as_mut() {
      self
        .worker
        .with_event_loop(coverage_collector.stop_collecting().boxed_local())
        .await?;
    }

    Ok(self.worker.exit_code())
  }

  pub async fn run_for_watcher(self) -> Result<(), AnyError> {
    /// The FileWatcherModuleExecutor provides module execution with safe dispatching of life-cycle events by tracking the
    /// state of any pending events and emitting accordingly on drop in the case of a future
    /// cancellation.
    struct FileWatcherModuleExecutor {
      inner: CliMainWorker,
      pending_unload: bool,
    }

    impl FileWatcherModuleExecutor {
      pub fn new(worker: CliMainWorker) -> FileWatcherModuleExecutor {
        FileWatcherModuleExecutor {
          inner: worker,
          pending_unload: false,
        }
      }

      /// Execute the given main module emitting load and unload events before and after execution
      /// respectively.
      pub async fn execute(&mut self) -> Result<(), AnyError> {
        self.inner.execute_main_module_possibly_with_npm().await?;
        self
          .inner
          .worker
          .dispatch_load_event(located_script_name!())?;
        self.pending_unload = true;

        let result = loop {
          match self.inner.worker.run_event_loop(false).await {
            Ok(()) => {}
            Err(error) => break Err(error),
          }
          match self
            .inner
            .worker
            .dispatch_beforeunload_event(located_script_name!())
          {
            Ok(default_prevented) if default_prevented => {} // continue loop
            Ok(_) => break Ok(()),
            Err(error) => break Err(error),
          }
        };
        self.pending_unload = false;

        result?;

        self
          .inner
          .worker
          .dispatch_unload_event(located_script_name!())?;

        Ok(())
      }
    }

    impl Drop for FileWatcherModuleExecutor {
      fn drop(&mut self) {
        if self.pending_unload {
          let _ = self
            .inner
            .worker
            .dispatch_unload_event(located_script_name!());
        }
      }
    }

    let mut executor = FileWatcherModuleExecutor::new(self);
    executor.execute().await
  }

  pub async fn execute_main_module_possibly_with_npm(
    &mut self,
  ) -> Result<(), AnyError> {
    let id = self.worker.preload_main_module(&self.main_module).await?;
    self.evaluate_module_possibly_with_npm(id).await
  }

  pub async fn execute_side_module_possibly_with_npm(
    &mut self,
  ) -> Result<(), AnyError> {
    let id = self.worker.preload_side_module(&self.main_module).await?;
    self.evaluate_module_possibly_with_npm(id).await
  }

  async fn evaluate_module_possibly_with_npm(
    &mut self,
    id: ModuleId,
  ) -> Result<(), AnyError> {
    if self.shared.npm_resolver.has_packages()
      || self.shared.graph_container.graph().has_node_specifier
    {
      self.initialize_main_module_for_node()?;
    }
    self.worker.evaluate_module(id).await
  }

  fn initialize_main_module_for_node(&mut self) -> Result<(), AnyError> {
    deno_node::initialize_runtime(
      &mut self.worker.js_runtime,
      self.shared.options.has_node_modules_dir,
      self.shared.options.maybe_binary_npm_command_name.as_deref(),
    )?;

    Ok(())
  }

  pub async fn maybe_setup_coverage_collector(
    &mut self,
  ) -> Result<Option<CoverageCollector>, AnyError> {
    if let Some(coverage_dir) = &self.shared.options.coverage_dir {
      let session = self.worker.create_inspector_session().await;

      let coverage_dir = PathBuf::from(coverage_dir);
      let mut coverage_collector =
        tools::coverage::CoverageCollector::new(coverage_dir, session);
      self
        .worker
        .with_event_loop(coverage_collector.start_collecting().boxed_local())
        .await?;
      Ok(Some(coverage_collector))
    } else {
      Ok(None)
    }
  }
}

pub struct CliMainWorkerFactory {
  shared: Arc<SharedWorkerState>,
}

impl CliMainWorkerFactory {
  #[allow(clippy::too_many_arguments)]
  pub fn new(
    storage_key_resolver: StorageKeyResolver,
    npm_resolver: Arc<CliNpmResolver>,
    node_resolver: Arc<NodeResolver>,
    graph_container: Arc<ModuleGraphContainer>,
    blob_store: BlobStore,
    module_loader_factory: CliModuleLoaderFactory,
    root_cert_store: RootCertStore,
    node_fs: Arc<dyn deno_node::NodeFs>,
    maybe_inspector_server: Option<Arc<InspectorServer>>,
    options: CliMainWorkerOptions,
  ) -> Self {
    Self {
      shared: Arc::new(SharedWorkerState {
        options,
        storage_key_resolver,
        npm_resolver,
        node_resolver,
        graph_container,
        blob_store,
        broadcast_channel: Default::default(),
        shared_array_buffer_store: Default::default(),
        compiled_wasm_module_store: Default::default(),
        module_loader_factory,
        root_cert_store,
        node_fs,
        maybe_inspector_server,
      }),
    }
  }

  pub async fn create_main_worker(
    &self,
    main_module: ModuleSpecifier,
    permissions: PermissionsContainer,
  ) -> Result<CliMainWorker, AnyError> {
    self
      .create_custom_worker(
        main_module,
        permissions,
        vec![],
        Default::default(),
      )
      .await
  }

  pub async fn create_custom_worker(
    &self,
    main_module: ModuleSpecifier,
    permissions: PermissionsContainer,
    mut custom_extensions: Vec<Extension>,
    stdio: deno_runtime::deno_io::Stdio,
  ) -> Result<CliMainWorker, AnyError> {
    let shared = &self.shared;
    let (main_module, is_main_cjs) = if let Ok(package_ref) =
      // 从 npm 指示符解析出 name、version 等信息
    NpmPackageReqReference::from_specifier(
        &main_module,
        ) {
    // 往 npm resolver 中添加 npm package 依赖信息
      shared
        .npm_resolver
        .add_package_reqs(vec![package_ref.req.clone()])
        .await?;
      let node_resolution =
        shared.node_resolver.resolve_binary_export(&package_ref)?;
      // 判断主入口模块是否是 cjs 模块
    let is_main_cjs = matches!(node_resolution, NodeResolution::CommonJs(_));
      (node_resolution.into_url(), is_main_cjs)
    } else if shared.options.is_npm_main {
      // 判断是否是 npm 包
    let node_resolution =
        shared.node_resolver.url_to_node_resolution(main_module)?;
      // 判断是否是 cjs 模块
    let is_main_cjs = matches!(node_resolution, NodeResolution::CommonJs(_));
      (node_resolution.into_url(), is_main_cjs)
    } else {
      // 不是 cjs 模块
    (main_module, false)
    };

    // 创建模块加载器
  let module_loader =
      Rc::new(shared.module_loader_factory.create_for_main(
        PermissionsContainer::allow_all(),
        permissions.clone(),
      ));
    // 是否开启了检测服务器
  let maybe_inspector_server = shared.maybe_inspector_server.clone();

    // 创建 web_worker 回调
  let create_web_worker_cb =
      create_web_worker_callback(shared.clone(), stdio.clone());
    // web_worker 预加载模块回调
  let web_worker_preload_module_cb =
      create_web_worker_preload_module_callback(shared);
    // web_worker 预执行模块回调
  let web_worker_pre_execute_module_cb =
      create_web_worker_pre_execute_module_callback(shared.clone());

    let maybe_storage_key = shared
      .storage_key_resolver
      .resolve_storage_key(&main_module);
    let origin_storage_dir = maybe_storage_key.as_ref().map(|key| {
      shared
        .options
        .origin_data_folder_path
        .join(checksum::gen(&[key.as_bytes()]))
    });
    let cache_storage_dir = maybe_storage_key.map(|key| {
      // TODO(@satyarohith): storage quota management
      // Note: we currently use temp_dir() to avoid managing storage size.
      std::env::temp_dir()
        .join("deno_cache")
        .join(checksum::gen(&[key.as_bytes()]))
    });

    // 加载 npm 加载器拓展
  let mut extensions = ops::cli_exts(shared.npm_resolver.clone());
    extensions.append(&mut custom_extensions);

    // worker 启动的配置
  let options = WorkerOptions {
      bootstrap: BootstrapOptions {
        args: shared.options.argv.clone(),
        cpu_count: std::thread::available_parallelism()
          .map(|p| p.get())
          .unwrap_or(1),
        debug_flag: shared.options.debug,
        enable_testing_features: shared.options.enable_testing_features,
        locale: deno_core::v8::icu::get_language_tag(),
        location: shared.options.location.clone(),
        no_color: !colors::use_color(),
        is_tty: colors::is_tty(),
        runtime_version: version::deno().to_string(),
        ts_version: version::TYPESCRIPT.to_string(),
        unstable: shared.options.unstable,
        user_agent: version::get_user_agent().to_string(),
        inspect: shared.options.is_inspecting,
      },
      extensions,
      // 启动快照
    startup_snapshot: Some(crate::js::deno_isolate_init()),
      unsafely_ignore_certificate_errors: shared
        .options
        .unsafely_ignore_certificate_errors
        .clone(),
      root_cert_store: Some(shared.root_cert_store.clone()),
      seed: shared.options.seed,
      source_map_getter: Some(Box::new(module_loader.clone())),
      format_js_error_fn: Some(Arc::new(format_js_error)),
      create_web_worker_cb,
      web_worker_preload_module_cb,
      web_worker_pre_execute_module_cb,
      maybe_inspector_server,
      should_break_on_first_statement: shared.options.inspect_brk,
      should_wait_for_inspector_session: shared.options.inspect_wait,
      module_loader,
      node_fs: Some(shared.node_fs.clone()),
      npm_resolver: Some(shared.npm_resolver.clone()),
      get_error_class_fn: Some(&errors::get_error_class_name),
      cache_storage_dir,
      origin_storage_dir,
      blob_store: shared.blob_store.clone(),
      broadcast_channel: shared.broadcast_channel.clone(),
      shared_array_buffer_store: Some(shared.shared_array_buffer_store.clone()),
      compiled_wasm_module_store: Some(
        shared.compiled_wasm_module_store.clone(),
      ),
      stdio,
    };

    // 创建一个用于启动的主 worker
  let worker = MainWorker::bootstrap_from_options(
      main_module.clone(),
      permissions,
      options,
    );

    Ok(CliMainWorker {
      main_module,
      is_main_cjs,
      worker,
      shared: shared.clone(),
    })
  }
}

// TODO(bartlomieju): this callback could have default value
// and not be required
fn create_web_worker_preload_module_callback(
  _shared: &Arc<SharedWorkerState>,
) -> Arc<WorkerEventCb> {
  Arc::new(move |worker| {
    let fut = async move { Ok(worker) };
    LocalFutureObj::new(Box::new(fut))
  })
}

fn create_web_worker_pre_execute_module_callback(
  shared: Arc<SharedWorkerState>,
) -> Arc<WorkerEventCb> {
  Arc::new(move |mut worker| {
    let shared = shared.clone();
    let fut = async move {
      // this will be up to date after pre-load
      if shared.npm_resolver.has_packages() {
        deno_node::initialize_runtime(
          &mut worker.js_runtime,
          shared.options.has_node_modules_dir,
          None,
        )?;
      }

      Ok(worker)
    };
    LocalFutureObj::new(Box::new(fut))
  })
}

fn create_web_worker_callback(
  shared: Arc<SharedWorkerState>,
  stdio: deno_runtime::deno_io::Stdio,
) -> Arc<CreateWebWorkerCb> {
  Arc::new(move |args| {
    let maybe_inspector_server = shared.maybe_inspector_server.clone();

    // 模块加载器
    let module_loader =
      Rc::new(shared.module_loader_factory.create_for_worker(
        args.parent_permissions.clone(),
        args.permissions.clone(),
      ));
    
    let create_web_worker_cb =
      create_web_worker_callback(shared.clone(), stdio.clone());
    let preload_module_cb = create_web_worker_preload_module_callback(&shared);
    let pre_execute_module_cb =
      create_web_worker_pre_execute_module_callback(shared.clone());

    let extensions = ops::cli_exts(shared.npm_resolver.clone());

    let maybe_storage_key = shared
      .storage_key_resolver
      .resolve_storage_key(&args.main_module);
    let cache_storage_dir = maybe_storage_key.map(|key| {
      // TODO(@satyarohith): storage quota management
      // Note: we currently use temp_dir() to avoid managing storage size.
      std::env::temp_dir()
        .join("deno_cache")
        .join(checksum::gen(&[key.as_bytes()]))
    });

    let options = WebWorkerOptions {
      bootstrap: BootstrapOptions {
        args: shared.options.argv.clone(),
        cpu_count: std::thread::available_parallelism()
          .map(|p| p.get())
          .unwrap_or(1),
        debug_flag: shared.options.debug,
        enable_testing_features: shared.options.enable_testing_features,
        locale: deno_core::v8::icu::get_language_tag(),
        location: Some(args.main_module.clone()),
        no_color: !colors::use_color(),
        is_tty: colors::is_tty(),
        runtime_version: version::deno().to_string(),
        ts_version: version::TYPESCRIPT.to_string(),
        unstable: shared.options.unstable,
        user_agent: version::get_user_agent().to_string(),
        inspect: shared.options.is_inspecting,
      },
      extensions,
      startup_snapshot: Some(crate::js::deno_isolate_init()),
      unsafely_ignore_certificate_errors: shared
        .options
        .unsafely_ignore_certificate_errors
        .clone(),
      root_cert_store: Some(shared.root_cert_store.clone()),
      seed: shared.options.seed,
      create_web_worker_cb,
      preload_module_cb,
      pre_execute_module_cb,
      format_js_error_fn: Some(Arc::new(format_js_error)),
      source_map_getter: Some(Box::new(module_loader.clone())),
      module_loader,
      node_fs: Some(shared.node_fs.clone()),
      npm_resolver: Some(shared.npm_resolver.clone()),
      worker_type: args.worker_type,
      maybe_inspector_server,
      get_error_class_fn: Some(&errors::get_error_class_name),
      blob_store: shared.blob_store.clone(),
      broadcast_channel: shared.broadcast_channel.clone(),
      shared_array_buffer_store: Some(shared.shared_array_buffer_store.clone()),
      compiled_wasm_module_store: Some(
        shared.compiled_wasm_module_store.clone(),
      ),
      stdio: stdio.clone(),
      cache_storage_dir,
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

#[cfg(test)]
mod tests {
  use std::rc::Rc;

  use super::*;
  use deno_core::resolve_path;
  use deno_core::FsModuleLoader;
  use deno_runtime::deno_broadcast_channel::InMemoryBroadcastChannel;
  use deno_runtime::deno_web::BlobStore;
  use deno_runtime::permissions::Permissions;

  fn create_test_worker() -> MainWorker {
    let main_module =
      resolve_path("./hello.js", &std::env::current_dir().unwrap()).unwrap();
    let permissions = PermissionsContainer::new(Permissions::default());

    let options = WorkerOptions {
      bootstrap: BootstrapOptions::default(),
      extensions: vec![],
      startup_snapshot: Some(crate::js::deno_isolate_init()),
      unsafely_ignore_certificate_errors: None,
      root_cert_store: None,
      seed: None,
      format_js_error_fn: None,
      source_map_getter: None,
      web_worker_preload_module_cb: Arc::new(|_| unreachable!()),
      web_worker_pre_execute_module_cb: Arc::new(|_| unreachable!()),
      create_web_worker_cb: Arc::new(|_| unreachable!()),
      maybe_inspector_server: None,
      should_break_on_first_statement: false,
      should_wait_for_inspector_session: false,
      module_loader: Rc::new(FsModuleLoader),
      node_fs: Some(Arc::new(deno_node::RealFs)),
      npm_resolver: None,
      get_error_class_fn: None,
      cache_storage_dir: None,
      origin_storage_dir: None,
      blob_store: BlobStore::default(),
      broadcast_channel: InMemoryBroadcastChannel::default(),
      shared_array_buffer_store: None,
      compiled_wasm_module_store: None,
      stdio: Default::default(),
    };

    MainWorker::bootstrap_from_options(main_module, permissions, options)
  }

  #[tokio::test]
  async fn execute_mod_esm_imports_a() {
    let p = test_util::testdata_path().join("runtime/esm_imports_a.js");
    let module_specifier = ModuleSpecifier::from_file_path(&p).unwrap();
    let mut worker = create_test_worker();
    let result = worker.execute_main_module(&module_specifier).await;
    if let Err(err) = result {
      eprintln!("execute_mod err {err:?}");
    }
    if let Err(e) = worker.run_event_loop(false).await {
      panic!("Future got unexpected error: {e:?}");
    }
  }

  #[tokio::test]
  async fn execute_mod_circular() {
    let p = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
      .parent()
      .unwrap()
      .join("tests/circular1.js");
    let module_specifier = ModuleSpecifier::from_file_path(&p).unwrap();
    let mut worker = create_test_worker();
    let result = worker.execute_main_module(&module_specifier).await;
    if let Err(err) = result {
      eprintln!("execute_mod err {err:?}");
    }
    if let Err(e) = worker.run_event_loop(false).await {
      panic!("Future got unexpected error: {e:?}");
    }
  }

  #[tokio::test]
  async fn execute_mod_resolve_error() {
    // "foo" is not a valid module specifier so this should return an error.
    let mut worker = create_test_worker();
    let module_specifier =
      resolve_path("./does-not-exist", &std::env::current_dir().unwrap())
        .unwrap();
    let result = worker.execute_main_module(&module_specifier).await;
    assert!(result.is_err());
  }

  #[tokio::test]
  async fn execute_mod_002_hello() {
    // This assumes cwd is project root (an assumption made throughout the
    // tests).
    let mut worker = create_test_worker();
    let p = test_util::testdata_path().join("run/001_hello.js");
    let module_specifier = ModuleSpecifier::from_file_path(&p).unwrap();
    let result = worker.execute_main_module(&module_specifier).await;
    assert!(result.is_ok());
  }
}
