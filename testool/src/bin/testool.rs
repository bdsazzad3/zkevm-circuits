//! Execute the bytecode from an empty state and run the EVM and State circuits

use anyhow::{bail, Result};
use clap::Parser;
use log::info;
use std::{collections::HashSet, path::PathBuf, time::SystemTime};
use strum_macros::EnumString;
use testool::{
    compiler::Compiler,
    config::Config,
    config::TestSuite,
    load_tests,
    statetest::{
        load_statetests_suite, run_statetests_suite, run_test, CircuitsConfig, ResultLevel,
        Results, StateTest,
    },
    utils, write_test_ids, CODEHASH_FILE, REPORT_FOLDER,
};

#[allow(non_camel_case_types)]
#[derive(PartialEq, Parser, EnumString, Debug, Clone, Copy)]
enum Circuits {
    basic,
    sc,
}

/// EVM test vectors utility
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Suite (by default is "default")
    #[clap(long, default_value = "default")]
    suite: String,

    /// Execute only one test and dump the results
    #[clap(long)]
    inspect: Option<String>,

    /// Do not execute any test, just list collected tests
    #[clap(long)]
    ls: bool,

    /// Cache execution results, default to be latest result file
    #[clap(long)]
    cache: Option<PathBuf>,

    /// do not use cache
    #[clap(long)]
    use_cache: bool,

    /// whitelist level from cache result
    #[clap(short, long, value_parser, value_delimiter = ',')]
    levels: Vec<ResultLevel>,

    /// Generates log and and html file with info.
    #[clap(long)]
    report: bool,

    /// Run statetest in oneliner spec
    #[clap(long)]
    oneliner: Option<String>,

    /// Circuits to execute, can be basic (evm only) or sc (supercircuit)
    #[clap(long)]
    circuits: Option<Circuits>,

    /// Specify a file including test IDs to run these tests
    #[clap(long)]
    test_ids: Option<PathBuf>,

    /// Specify a file excluding test IDs to run these tests
    #[clap(long)]
    exclude_test_ids: Option<PathBuf>,

    /// Verbose
    #[clap(short, long)]
    v: bool,
}

fn run_single_test(
    test: StateTest,
    suite: TestSuite,
    circuits_config: CircuitsConfig,
) -> Result<()> {
    log::info!("run single test {}", &test);
    let circuits_config = CircuitsConfig {
        verbose: true,
        super_circuit: circuits_config.super_circuit,
    };
    //let trace = geth_trace(test.clone())?;
    //crate::utils::print_trace(trace)?;
    log::info!("result={:?}", run_test(test, suite, circuits_config));
    Ok(())
}

fn go() -> Result<()> {
    //  RAYON_NUM_THREADS=1 RUST_BACKTRACE=1 cargo run -- --path
    // "tests/src/GeneralStateTestsFiller/**/" --skip-state-circuit

    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let args = Args::parse();

    let mut circuits_config = CircuitsConfig::default();
    if args.circuits == Some(Circuits::sc) {
        circuits_config.super_circuit = true;
    }

    if let Some(oneliner) = &args.oneliner {
        let test = StateTest::parse_oneline_spec(oneliner)?;
        run_single_test(test, Default::default(), circuits_config)?;
        return Ok(());
    }

    let config = Config::load()?;

    log::info!("Using suite '{}'", args.suite);
    log::info!("Parsing and compiling tests...");
    let compiler = Compiler::new(true, Some(PathBuf::from(CODEHASH_FILE)))?;
    let suite = config.suite(&args.suite)?.clone();
    let mut state_tests = load_statetests_suite(&suite, config, compiler)?;
    log::info!(
        "{} tests collected in {}",
        state_tests.len(),
        suite.paths.join(", ")
    );

    if args.ls {
        let mut list: Vec<_> = state_tests.into_iter().map(|t| t.id).collect();
        list.sort();
        write_test_ids(list.as_slice())?;
        for test in list {
            info!("{}", test);
        }
        return Ok(());
    }
    if let Some(test_id) = args.inspect {
        // Test only one and return
        let mut state_tests_filtered: Vec<_> =
            state_tests.iter().filter(|t| t.id == test_id).collect();
        if state_tests_filtered.is_empty() {
            info!(
                "Test '{}' not found but found some that partially matches:",
                test_id
            );
            for test in state_tests.iter().filter(|t| t.id.contains(&test_id)) {
                info!("{}", test.id);
            }
            bail!("test '{}' not found", test_id);
        }
        run_single_test(
            state_tests_filtered.remove(0).clone(),
            suite,
            circuits_config,
        )?;
        return Ok(());
    };

    // It is better to sue deterministic testing order.
    // If there is a list, follow list.
    // If not, order by test id.
    load_tests(&mut state_tests, args.test_ids, args.exclude_test_ids)?;

    if args.report {
        let git_hash = utils::current_git_commit()?;
        let git_submodule_tests_hash = utils::current_submodule_git_commit()?;
        let timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        std::fs::create_dir_all(REPORT_FOLDER)?;
        let csv_filename = format!(
            "{}/{}.{}.{}.csv",
            REPORT_FOLDER, args.suite, timestamp, git_hash
        );
        let html_filename = format!(
            "{}/{}.{}.{}.html",
            REPORT_FOLDER, args.suite, timestamp, git_hash
        );

        let cache_file_name = if !args.use_cache {
            None
        } else {
            let mut history_reports =
                glob::glob(format!("{REPORT_FOLDER}/{}.*.*.csv", args.suite).as_str())?
                    .collect::<Result<Vec<PathBuf>, glob::GlobError>>()?
                    .into_iter()
                    .map(|path| {
                        path.metadata()
                            .and_then(|meta| meta.created())
                            .map(|created| (path, created))
                    })
                    .collect::<Result<Vec<(PathBuf, SystemTime)>, std::io::Error>>()?;
            // sort by timestamp
            history_reports.sort_by_key(|(_, created)| *created);
            // use latest cache if exists
            args.cache
                .or_else(|| history_reports.pop().map(|(path, _)| path))
        };

        // when running a report, the tests result of the containing cache file
        // are used, but by default removing all Ignored tests
        // Another way is to skip the test which level not in whitelist_levels
        let mut previous_results = if let Some(cache_filename) = cache_file_name {
            let whitelist_levels = HashSet::<ResultLevel>::from_iter(args.levels);

            let mut previous_results = Results::from_file(cache_filename).unwrap();

            info!("loaded {} test results", previous_results.tests.len());
            if !whitelist_levels.is_empty() {
                // if whitelist is provided, test not in whitelist will be skip
                previous_results
                    .tests
                    .retain(|_, test| !whitelist_levels.contains(&test.level));
            } else {
                // by default skip ignore and success tests
                previous_results.tests.retain(|_, test| {
                    test.level == ResultLevel::Ignored || test.level == ResultLevel::Success
                });
            }

            previous_results
        } else {
            Results::default()
        };

        previous_results.set_cache(PathBuf::from(csv_filename));
        previous_results.write_cache()?;
        run_statetests_suite(state_tests, &circuits_config, &suite, &mut previous_results)?;

        // filter non-csv files and files from the same commit
        let mut files: Vec<_> = std::fs::read_dir(REPORT_FOLDER)
            .unwrap()
            .filter_map(|f| {
                let filename = f.unwrap().file_name().to_str().unwrap().to_string();
                (filename.starts_with(&format!("{}.", args.suite))
                    && filename.ends_with(".csv")
                    && !filename.contains(&format!(".{git_hash}.")))
                .then_some(filename)
            })
            .collect();

        files.sort_by(|f, s| s.cmp(f));
        let previous = if !files.is_empty() {
            let file = files.remove(0);
            let path = format!("{REPORT_FOLDER}/{file}");
            info!("Comparing with previous results in {path}");
            Some((file, Results::from_file(PathBuf::from(path))?))
        } else {
            None
        };
        let report = previous_results.report(previous);
        std::fs::write(&html_filename, report.gen_html(git_submodule_tests_hash)?)?;

        report.print_tty()?;
        info!("{}", html_filename);
    } else {
        let mut results = if let Some(cache_filename) = args.cache {
            Results::with_cache(cache_filename)?
        } else {
            Results::default()
        };

        log::info!("Executing...");
        run_statetests_suite(state_tests, &circuits_config, &suite, &mut results)?;
        let success = results.success();

        log::info!("Generating report...");
        results.report(None).print_tty()?;

        if !success {
            std::process::exit(1);
        }
    }

    Ok(())
}

fn main() {
    if let Err(err) = go() {
        eprintln!("Error found {err}");
    }
}