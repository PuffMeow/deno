// Copyright 2018-2023 the Deno authors. All rights reserved. MIT license.

mod args;
mod auth_tokens;
mod cache;
mod deno_std;
mod emit;
mod errors;
mod file_fetcher;
mod graph_util;
mod http_util;
mod js;
mod lsp;
mod module_loader;
mod napi;
mod node;
mod npm;
mod ops;
mod proc_state;
mod resolver;
mod standalone;
mod tools;
mod tsc;
mod util;
mod version;
mod worker;

use crate::args::flags_from_vec;
use crate::args::DenoSubcommand;
use crate::args::Flags;
use crate::proc_state::ProcState;
use crate::resolver::CliGraphResolver;
use crate::util::display;
use crate::util::v8::get_v8_flags_from_env;
use crate::util::v8::init_v8_flags;

use args::CliOptions;
use deno_core::anyhow::Context;
use deno_core::error::AnyError;
use deno_core::error::JsError;
use deno_runtime::colors;
use deno_runtime::fmt_errors::format_js_error;
use deno_runtime::tokio_util::run_local;
use std::env;
use std::env::current_exe;
use std::path::PathBuf;

async fn run_subcommand(flags: Flags) -> Result<i32, AnyError> {
  match flags.subcommand.clone() {
    DenoSubcommand::Bench(bench_flags) => {
      let cli_options = CliOptions::from_flags(flags)?;
      let bench_options = cli_options.resolve_bench_options(bench_flags)?;
      if cli_options.watch_paths().is_some() {
        tools::bench::run_benchmarks_with_watch(cli_options, bench_options)
          .await?;
      } else {
        tools::bench::run_benchmarks(cli_options, bench_options).await?;
      }
      Ok(0)
    }
    DenoSubcommand::Bundle(bundle_flags) => {
      tools::bundle::bundle(flags, bundle_flags).await?;
      Ok(0)
    }
    DenoSubcommand::Doc(doc_flags) => {
      tools::doc::print_docs(flags, doc_flags).await?;
      Ok(0)
    }
    DenoSubcommand::Eval(eval_flags) => {
      tools::run::eval_command(flags, eval_flags).await
    }
    DenoSubcommand::Cache(cache_flags) => {
      let ps = ProcState::from_flags(flags).await?;
      ps.module_load_preparer
        .load_and_type_check_files(&cache_flags.files)
        .await?;
      ps.emitter.cache_module_emits(&ps.graph_container.graph())?;
      Ok(0)
    }
    DenoSubcommand::Check(check_flags) => {
      let ps = ProcState::from_flags(flags).await?;
      ps.module_load_preparer
        .load_and_type_check_files(&check_flags.files)
        .await?;
      Ok(0)
    }
    DenoSubcommand::Compile(compile_flags) => {
      tools::standalone::compile(flags, compile_flags).await?;
      Ok(0)
    }
    DenoSubcommand::Coverage(coverage_flags) => {
      tools::coverage::cover_files(flags, coverage_flags).await?;
      Ok(0)
    }
    DenoSubcommand::Fmt(fmt_flags) => {
      let cli_options = CliOptions::from_flags(flags.clone())?;
      let fmt_options = cli_options.resolve_fmt_options(fmt_flags)?;
      tools::fmt::format(cli_options, fmt_options).await?;
      Ok(0)
    }
    DenoSubcommand::Init(init_flags) => {
      tools::init::init_project(init_flags).await?;
      Ok(0)
    }
    DenoSubcommand::Info(info_flags) => {
      tools::info::info(flags, info_flags).await?;
      Ok(0)
    }
    DenoSubcommand::Install(install_flags) => {
      tools::installer::install_command(flags, install_flags).await?;
      Ok(0)
    }
    DenoSubcommand::Uninstall(uninstall_flags) => {
      tools::installer::uninstall(uninstall_flags.name, uninstall_flags.root)?;
      Ok(0)
    }
    DenoSubcommand::Lsp => {
      lsp::start().await?;
      Ok(0)
    }
    DenoSubcommand::Lint(lint_flags) => {
      if lint_flags.rules {
        tools::lint::print_rules_list(lint_flags.json);
      } else {
        let cli_options = CliOptions::from_flags(flags)?;
        let lint_options = cli_options.resolve_lint_options(lint_flags)?;
        tools::lint::lint(cli_options, lint_options).await?;
      }
      Ok(0)
    }
    DenoSubcommand::Repl(repl_flags) => {
      tools::repl::run(flags, repl_flags).await
    }
    DenoSubcommand::Run(run_flags) => {
      if run_flags.is_stdin() {
        tools::run::run_from_stdin(flags).await
      } else {
        tools::run::run_script(flags).await
      }
    }
    DenoSubcommand::Task(task_flags) => {
      tools::task::execute_script(flags, task_flags).await
    }
    DenoSubcommand::Test(test_flags) => {
      if let Some(ref coverage_dir) = flags.coverage_dir {
        std::fs::create_dir_all(coverage_dir)
          .with_context(|| format!("Failed creating: {coverage_dir}"))?;
        // this is set in order to ensure spawned processes use the same
        // coverage directory
        env::set_var(
          "DENO_UNSTABLE_COVERAGE_DIR",
          PathBuf::from(coverage_dir).canonicalize()?,
        );
      }
      let cli_options = CliOptions::from_flags(flags)?;
      let test_options = cli_options.resolve_test_options(test_flags)?;

      if cli_options.watch_paths().is_some() {
        tools::test::run_tests_with_watch(cli_options, test_options).await?;
      } else {
        tools::test::run_tests(cli_options, test_options).await?;
      }

      Ok(0)
    }
    DenoSubcommand::Completions(completions_flags) => {
      display::write_to_stdout_ignore_sigpipe(&completions_flags.buf)?;
      Ok(0)
    }
    DenoSubcommand::Types => {
      let types = tsc::get_types_declaration_file_text(flags.unstable);
      display::write_to_stdout_ignore_sigpipe(types.as_bytes())?;
      Ok(0)
    }
    DenoSubcommand::Upgrade(upgrade_flags) => {
      tools::upgrade::upgrade(flags, upgrade_flags).await?;
      Ok(0)
    }
    DenoSubcommand::Vendor(vendor_flags) => {
      tools::vendor::vendor(flags, vendor_flags).await?;
      Ok(0)
    }
  }
}

fn setup_panic_hook() {
  // This function does two things inside of the panic hook:
  // - Tokio does not exit the process when a task panics, so we define a custom
  //   panic hook to implement this behaviour.
  // - We print a message to stderr to indicate that this is a bug in Deno, and
  //   should be reported to us.
  let orig_hook = std::panic::take_hook();
  std::panic::set_hook(Box::new(move |panic_info| {
    eprintln!("\n============================================================");
    eprintln!("Deno has panicked. This is a bug in Deno. Please report this");
    eprintln!("at https://github.com/denoland/deno/issues/new.");
    eprintln!("If you can reliably reproduce this panic, include the");
    eprintln!("reproduction steps and re-run with the RUST_BACKTRACE=1 env");
    eprintln!("var set and include the backtrace in your report.");
    eprintln!();
    eprintln!("Platform: {} {}", env::consts::OS, env::consts::ARCH);
    eprintln!("Version: {}", version::deno());
    eprintln!("Args: {:?}", env::args().collect::<Vec<_>>());
    eprintln!();
    orig_hook(panic_info);
    std::process::exit(1);
  }));
}

/// unwrap 取值或者错误时退出
fn unwrap_or_exit<T>(result: Result<T, AnyError>) -> T {
  match result {
    Ok(value) => value,
    Err(error) => {
      let mut error_string = format!("{error:?}");
      let mut error_code = 1;

      if let Some(e) = error.downcast_ref::<JsError>() {
        error_string = format_js_error(e);
      } else if let Some(e) = error.downcast_ref::<args::LockfileError>() {
        error_string = e.to_string();
        error_code = 10;
      }

      eprintln!(
        "{}: {}",
        colors::red_bold("error"),
        error_string.trim_start_matches("error: ")
      );
      std::process::exit(error_code);
    }
  }
}

// 主要命令行运行入口
pub fn main() {
  setup_panic_hook();

  util::unix::raise_fd_limit();
  util::windows::ensure_stdio_open();
  #[cfg(windows)]
  colors::enable_ansi(); // For Windows 10
  deno_runtime::permissions::set_prompt_callbacks(
    Box::new(util::draw_thread::DrawThread::hide),
    Box::new(util::draw_thread::DrawThread::show),
  );

  // 收集命令行参数
  let args: Vec<String> = env::args().collect();

  // 最后返回一个 future 任务
  let future = async move {
    let current_exe_path = current_exe()?;
    let standalone_res =
      match standalone::extract_standalone(&current_exe_path, args.clone())
        .await
      {
        // standalone 执行独立运行包。
        Ok(Some((metadata, eszip))) => standalone::run(eszip, metadata).await,
        Ok(None) => Ok(()),
        Err(err) => Err(err),
      };
    // TODO(bartlomieju): doesn't handle exit code set by the runtime properly
    unwrap_or_exit(standalone_res);

    // 处理一些权限系统，比如 --allow-net 等
    // 比如输入 deno run main.ts，会解析对应参数然后全部写入到 flags 变量中
    let flags = match flags_from_vec(args) {
      Ok(flags) => flags,
      Err(err @ clap::Error { .. })
        if err.kind() == clap::error::ErrorKind::DisplayHelp
          || err.kind() == clap::error::ErrorKind::DisplayVersion =>
      {
        err.print().unwrap();
        std::process::exit(0);
      }
      Err(err) => unwrap_or_exit(Err(AnyError::from(err))),
    };

    // 初始化 v8 引擎参数，如果参数设置有错就直接退出
    init_v8_flags(&flags.v8_flags, get_v8_flags_from_env());

    // 初始化 logger，控制台日志
    util::logger::init(flags.log_level);

    // 运行命令行 比如 deno run 匹配 DenoSubcommand::RUN
    run_subcommand(flags).await
  };

  // unwrap_or_exit 使用 anyhow 来处理错误，打印错误信息并退出进程
  // run_local创建 tokio 异步运行时，最大线程数 32 个
  let exit_code = unwrap_or_exit(run_local(future));

  std::process::exit(exit_code);
}
