
extern crate windows;
extern crate libafl;
extern crate libafl_bolts;
extern crate windows_core;

#[cfg(windows)]
use std::ptr::write_volatile;
use std::{collections::HashMap, convert::TryInto, ffi::{OsStr, OsString}, path::PathBuf, ptr::write, time::Instant};


#[cfg(feature = "tui")]
use libafl::monitors::tui::TuiMonitor;
#[cfg(not(feature = "tui"))]
use libafl::monitors::SimpleMonitor;
use libafl::{
    Evaluator, corpus::{Corpus, InMemoryCorpus, OnDiskCorpus}, events::SimpleEventManager, executors::{ExitKind, InProcessExecutor}, feedbacks::{CrashFeedback, MaxMapFeedback}, fuzzer::{Fuzzer, StdFuzzer}, generators::RandPrintablesGenerator, inputs::{BytesInput, HasTargetBytes, ValueInput}, mutators::{havoc_mutations::havoc_mutations, scheduled::HavocScheduledMutator}, observers::ConstMapObserver, schedulers::QueueScheduler, stages::mutational::StdMutationalStage, state::StdState
};
use libafl_bolts::{
    current_nanos, nonnull_raw_mut, nonzero, rands::StdRand, tuples::tuple_list, AsSlice,
};
use windows::{Win32::System::Pipes::SetNamedPipeHandleState, Win32::{self, Foundation::{GENERIC_READ, GENERIC_WRITE, HANDLE}, Security::Authentication::Identity::DOMAIN_LOCKOUT_ADMINS, Storage::FileSystem::{CreateFileA, FILE_CREATION_DISPOSITION, FILE_FLAGS_AND_ATTRIBUTES, FILE_SHARE_MODE, OPEN_EXISTING, ReadFile, WriteFile}, System::{Pipes::{PIPE_READMODE_MESSAGE, PIPE_WAIT}, Threading::Sleep}}, core::s};

/// Coverage map with explicit assignments due to the lack of instrumentation
const SIGNALS_LEN: usize = 1088;
static mut SIGNALS: [u8; SIGNALS_LEN] = [0; SIGNALS_LEN];
static mut SIGNALS_PTR: *mut u8 = &raw mut SIGNALS as _;

static mut BUFSIZE: usize = 0;

/// Assign a signal to the signals map
fn signals_set(idx: usize) {
    unsafe { write_volatile(SIGNALS_PTR.add(idx), 1) };
}

fn signal_reset() {
    for i in 0..SIGNALS_LEN {
        unsafe { write_volatile(SIGNALS_PTR.add(i), 0) };
    }
}

enum WB {
    Hook(u32),
    Done,
    Crash,
}
fn read(f: HANDLE) -> WB {
    let mut y = [0u8; 5];
    unsafe {
        ReadFile(f, Some(&mut y), None, None).unwrap();
    }

    match y[0] {
        0x01 => {
            let b0 = y[1] as u32;
            let b1 = y[2] as u32;
            let b2 = y[3] as u32;
            let b3 = y[4] as u32;
            let num = b0 | (b1<<8) | (b2<<16) | (b3<<24);
            return WB::Hook(num);
        },
        0x02 => {
            return match y[1] {
                0xAA => WB::Crash,
                0x64 => WB::Done,
                _ => panic!("invalid 0x02"),
            };
        },
        _ => panic!("invalid")
    }
}


fn write_buf(f: HANDLE, x: &[u8]) {
    unsafe { WriteFile(f, Some(x), None, None).unwrap(); }
}

static mut curr_id: usize = 3;

fn get_sigid(hash: u32, sigids: &mut HashMap<u32, usize>) -> usize {
    if sigids.contains_key(&hash) {
        return *sigids.get(&hash).unwrap();
    }


    unsafe { curr_id += 1; }
    unsafe { sigids.insert(hash, curr_id) };

    return unsafe { curr_id };
}

fn do_harness(f: HANDLE, x: &[u8], sigids: &mut HashMap<u32, usize>) -> bool {
    write_buf(f, x);
    loop {
        match read(f) {
            WB::Crash => {
                println!("crash");
                unsafe {
                    write_volatile(std::ptr::null_mut::<u32>(), 0);
                }
                return true;
            },
            WB::Done => {
                return false;
            },
            WB::Hook(hash) => {
                signals_set(2);
                get_sigid(hash, sigids);
                get_sigid(hash, sigids);
                signals_set(get_sigid(hash, sigids));
            }
        }
    }

}

pub fn main() {
    unsafe {
        BUFSIZE = std::env::args().nth(1).unwrap().parse().unwrap();
    }

    unsafe { Sleep(1000) };
    let mut sigids = HashMap::new();

    let pipe_path = std::env::args().nth(2).unwrap();

    println!("bufsize {} at path {}", unsafe { BUFSIZE }, pipe_path );

    // https://kennykerr.ca/rust-getting-started/string-tutorial.html
    let mut pipe_path_a = Vec::from(pipe_path.as_bytes());
    pipe_path_a.push(0);

    // for x in &pipe_path_a {
    //     println!("{}", char::from_u32(*x as u32).unwrap() );
    // }
    let f = unsafe { CreateFileA(windows_core::PCSTR(pipe_path_a.as_ptr()), GENERIC_READ.0 | GENERIC_WRITE.0, FILE_SHARE_MODE(0), None, OPEN_EXISTING as FILE_CREATION_DISPOSITION, FILE_FLAGS_AND_ATTRIBUTES(0), None).unwrap() };

    // unsafe { let mut mode = PIPE_READMODE_MESSAGE.0 | PIPE_WAIT.0; SetNamedPipeHandleState(f, &mode, None, None) };

    let start = Instant::now();

    env_logger::init();
    // The closure that we want to fuzz
    let mut harness = |input: &BytesInput| {
        let target = input.target_bytes();
        let buf = target.as_slice();
        signal_reset();
        if buf.len() == unsafe { BUFSIZE } {
            signals_set(0);
            // signals_set(1);
            if do_harness(f, buf[0..unsafe{ BUFSIZE }].try_into().unwrap(), &mut sigids) {
                println!("CRASH TOOK {:?}", start.elapsed());
            }
        }
        ExitKind::Ok
    };

    // Create an observation channel using the signals map
    let observer = unsafe { ConstMapObserver::from_mut_ptr("signals", nonnull_raw_mut!(SIGNALS)) };

    // Feedback to rate the interestingness of an input
    let mut feedback = MaxMapFeedback::new(&observer);

    // A feedback to choose if an input is a solution or not
    let mut objective = CrashFeedback::new();

    // create a State from scratch
    let mut state = StdState::new(
        // RNG
        StdRand::with_seed(current_nanos()),
        // Corpus that will be evolved, we keep it in memory for performance
        InMemoryCorpus::new(),
        // Corpus in which we store solutions (crashes in this example),
        // on disk so the user can get them after stopping the fuzzer
        OnDiskCorpus::new(PathBuf::from("./crashes")).unwrap(),
        // States of the feedbacks.
        // The feedbacks can report the data that should persist in the State.
        &mut feedback,
        // Same for objective feedbacks
        &mut objective,
    )
    .unwrap();


    // The Monitor trait define how the fuzzer stats are displayed to the user
    #[cfg(not(feature = "tui"))]
    let mon = SimpleMonitor::new(|s| println!("{s}"));
    #[cfg(feature = "tui")]
    let mon = TuiMonitor::builder()
        .title("Baby Fuzzer")
        .enhanced_graphics(false)
        .build();

    // The event manager handle the various events generated during the fuzzing loop
    // such as the notification of the addition of a new item to the corpus
    let mut mgr = SimpleEventManager::new(mon);

    // A queue policy to get testcasess from the corpus
    let scheduler = QueueScheduler::new();

    // A fuzzer with feedbacks and a corpus scheduler
    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

    // Create the executor for an in-process function with just one observer
    let mut executor = InProcessExecutor::new(
        &mut harness,
        tuple_list!(observer),
        &mut fuzzer,
        &mut state,
        &mut mgr,
    )
    .expect("Failed to create the Executor");

    // Generator of printable bytearrays of max size 32
    let mut generator = RandPrintablesGenerator::new(nonzero!(32));

    // Generate 8 initial inputs
    state
        .generate_initial_inputs(&mut fuzzer, &mut executor, &mut generator, &mut mgr, 8)
        .expect("Failed to generate the initial corpus");

    // Setup a mutational stage with a basic bytes mutator
    let mutator = HavocScheduledMutator::new(havoc_mutations());
    let mut stages = tuple_list!(StdMutationalStage::new(mutator));

    let mut sample_buf= vec![];
    for _ in 0..unsafe{ BUFSIZE } {
        sample_buf.push(0u8);
    }

    fuzzer.add_input(&mut state, &mut executor, &mut mgr, ValueInput::new(sample_buf)).unwrap();

    fuzzer
        .fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)
        .expect("Error in the fuzzing loop");
}