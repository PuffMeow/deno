// Copyright 2018-2023 the Deno authors. All rights reserved. MIT license.

use std::io::Read;

use deno_ast::MediaType;
use deno_ast::ModuleSpecifier;
use deno_core::error::AnyError;
use deno_runtime::permissions::Permissions;
use deno_runtime::permissions::PermissionsContainer;

use crate::args::EvalFlags;
use crate::args::Flags;
use crate::file_fetcher::File;
use crate::proc_state::ProcState;
use crate::util;
use crate::worker::create_main_worker;

/// 运行指定的 js 文件
pub async fn run_script(flags: Flags) -> Result<i32, AnyError> {
  // 判断输入的权限指令是否正确，比如输入一个 --allow-unknow 就会报错
  if !flags.has_permission() && flags.has_permission_in_argv() {
    log::warn!(
      "{}",
      crate::colors::yellow(
        r#"Permission flags have likely been incorrectly set after the script argument.
To grant permissions, set them before the script argument. For example:
    deno run --allow-read=. main.js"#
      )
    );
  }

  if flags.watch.is_some() {
    return run_with_watch(flags).await;
  }

  // TODO(bartlomieju): actually I think it will also fail if there's an import
  // map specified and bare specifier is used on the command line - this should
  // probably call `ProcState::resolve` instead
  // ProcState 存储一个 deno 实例的状态，它的状态会被所有已经创建的 worker 共享
  // 内部存储了 deno 中会用到的二进制数据，可以跨线程传递数据的广播通道生产者和 sharedArrayBuffer
  // WASM 依赖信息，网络缓存、网络请求客户端，分析和翻译 node.js 代码，npm 的兼容和解析处理， 处理 TS 配置和类型检查，
  // 构建模块的依赖关系，处理模块以及预加载需要的数据等操作
  let ps = ProcState::from_flags(flags).await?;

  // Run a background task that checks for available upgrades. If an earlier
  // run of this background task found a new version of Deno.
  // 在后台运行一个检查器查看 deno 是否可以升级
  super::upgrade::check_for_upgrades(
    ps.http_client.clone(),
    ps.dir.upgrade_check_file_path(),
  );

  // 主入口模块，解析后返回一个 URL ，有多种解析模式，命令行标准输入、npm、远程、本地文件等
  let main_module = ps.options.resolve_main_module()?;

  // 获取运行的权限，具有内部可变性，可以跨线程，比如可以传递到 Web Worker
  let permissions = PermissionsContainer::new(Permissions::from_options(
    &ps.options.permissions_options(),
  )?);

  // 创建一个运行 js 程序的 worker
  let mut worker = create_main_worker(&ps, main_module, permissions).await?;

  // 启动 worker 运行程序
  let exit_code = worker.run().await?;
  Ok(exit_code)
}

pub async fn run_from_stdin(flags: Flags) -> Result<i32, AnyError> {
  let ps = ProcState::from_flags(flags).await?;
  let main_module = ps.options.resolve_main_module()?;

  let mut worker = create_main_worker(
    &ps,
    main_module.clone(),
    PermissionsContainer::new(Permissions::from_options(
      &ps.options.permissions_options(),
    )?),
  )
  .await?;

  let mut source = Vec::new();
  std::io::stdin().read_to_end(&mut source)?;
  // Create a dummy source file.
  let source_file = File {
    local: main_module.clone().to_file_path().unwrap(),
    maybe_types: None,
    media_type: MediaType::TypeScript,
    source: String::from_utf8(source)?.into(),
    specifier: main_module,
    maybe_headers: None,
  };
  // Save our fake file into file fetcher cache
  // to allow module access by TS compiler
  ps.file_fetcher.insert_cached(source_file);

  let exit_code = worker.run().await?;
  Ok(exit_code)
}

// TODO(bartlomieju): this function is not handling `exit_code` set by the runtime
// code properly.
async fn run_with_watch(flags: Flags) -> Result<i32, AnyError> {
  let (sender, receiver) = tokio::sync::mpsc::unbounded_channel();
  let mut ps =
    ProcState::from_flags_for_file_watcher(flags, sender.clone()).await?;
  let clear_screen = !ps.options.no_clear_screen();
  let main_module = ps.options.resolve_main_module()?;

  let operation = |main_module: ModuleSpecifier| {
    ps.reset_for_file_watcher();
    let ps = ps.clone();
    Ok(async move {
      let permissions = PermissionsContainer::new(Permissions::from_options(
        &ps.options.permissions_options(),
      )?);
      let worker = create_main_worker(&ps, main_module, permissions).await?;
      worker.run_for_watcher().await?;

      Ok(())
    })
  };

  util::file_watcher::watch_func2(
    receiver,
    operation,
    main_module,
    util::file_watcher::PrintConfig {
      job_name: "Process".to_string(),
      clear_screen,
    },
  )
  .await?;

  Ok(0)
}

pub async fn eval_command(
  flags: Flags,
  eval_flags: EvalFlags,
) -> Result<i32, AnyError> {
  let ps = ProcState::from_flags(flags).await?;
  let main_module = ps.options.resolve_main_module()?;
  let permissions = PermissionsContainer::new(Permissions::from_options(
    &ps.options.permissions_options(),
  )?);
  let mut worker =
    create_main_worker(&ps, main_module.clone(), permissions).await?;
  // Create a dummy source file.
  let source_code = if eval_flags.print {
    format!("console.log({})", eval_flags.code)
  } else {
    eval_flags.code
  }
  .into_bytes();

  let file = File {
    local: main_module.clone().to_file_path().unwrap(),
    maybe_types: None,
    media_type: MediaType::Unknown,
    source: String::from_utf8(source_code)?.into(),
    specifier: main_module,
    maybe_headers: None,
  };

  // Save our fake file into file fetcher cache
  // to allow module access by TS compiler.
  ps.file_fetcher.insert_cached(file);
  let exit_code = worker.run().await?;
  Ok(exit_code)
}
