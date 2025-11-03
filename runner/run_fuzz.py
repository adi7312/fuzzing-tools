import argparse
import os
import subprocess
import multiprocessing
from elftools.elf.elffile import ELFFile
import yaml


def abspath_if_not_none(path):
    return os.path.abspath(path) if path else None

def setup_system(no_setup):
    if no_setup:
        print("[*] Skipping system setup (--no-setup).")
        return
    print("[*] Setting up core dump pattern and disabling ASLR (sudo required)...")
    subprocess.run("echo core | sudo tee /proc/sys/kernel/core_pattern > /dev/null", shell=True)
    subprocess.run("echo 0 | sudo tee /proc/sys/kernel/randomize_va_space > /dev/null", shell=True)
    subprocess.run("ulimit -s unlimited > /dev/null",shell=True)
    subprocess.run("ulimit -v unlimited", shell=True)


def make_dir(path):
    os.makedirs(path, exist_ok=True)

def launch_cmd_in_screen(session_name, cmd, cwd=None):
    if cwd:
        wrapped = f"bash -lc 'cd \"{cwd}\" && {cmd}"
    else:
        wrapped = f"bash -lc '{cmd}'"
    screen_cmd = f"screen -dmS {session_name} {wrapped}"
    print(f"[+] screen session: {session_name} -> {cmd}")
    subprocess.run(screen_cmd, shell=True, check=False)

def launch_honggfuzz(core_id, input_dir, cluster_dir, crash_dir, stats_file, target, timeout, session_name, dictionary, workspace=None):
    workspace_arg = f"-W \"{workspace}\"" if workspace else ""
    dict_args = f"-w \"{dictionary}\"" if dictionary else ""
    sanitizers = f"-S --sanitizers_del_report true" if "asan" in target else ""
    cmd = (
        f"screen -dmS {session_name} "
        f"bash -lc 'taskset -c {core_id} timeout -s INT {timeout} "
        f"honggfuzz -n 1 -s -z "
        f"-i \"{input_dir}\" "
        f"-o \"{cluster_dir}\" "
        f"{workspace_arg} "
        f"--crashdir \"{crash_dir}\" "
        f"--statsfile \"{stats_file}\" "
        f"{dict_args}"
        f"-V "
        f"-U "
        f"{sanitizers} "
        f"-- \"{target}\"'"
    )
    print(f"[+] Launching {session_name} on core {core_id} -> {target}")
    print(cmd)
    subprocess.run(cmd, shell=True, check=False)

def launch_afl(core_id, input_dir, output_dir, target, timeout, session_name, dictionary, is_main, is_aflpp):
    fuzzer_id = session_name[-6:]
    if is_main:
        afl_mode = f"-M {fuzzer_id}"
    else:
        afl_mode = f"-S {fuzzer_id}"
    if not is_aflpp:
        afl_bin = "/home/ad1s0n/Tools/AFL/afl-fuzz" # maybe some config file? ENV would be better
    else:
        afl_bin = "afl-fuzz"
    
    if dictionary:
        dict_cmd = f"-x \"{dictionary}\""
    else:
        dict_cmd = f""

    cmd = (
        f"screen -dmS {session_name} "
        f"bash -lc 'taskset -c {core_id} timeout -s INT {timeout} "
        f"{afl_bin} -i \"{input_dir}\" -o \"{output_dir}\" {afl_mode} {dict_cmd} -m none "
        f"-- \"{target}\"'"
    )
    print(cmd)
    print(f"[+] Launching {session_name} on core {core_id} -> {target}")
    subprocess.run(cmd, shell=True, check=False)

def launch_symcc(core_id, fuzzer_id, concolic_bin, session_name, timeout, output_dir):
    cmd = (
        f"screen -dmS {session_name} "
        f"bash -lc 'taskset -c {core_id} timeout {timeout} "
        f"/home/ad1s0n/.cargo/bin/symcc_fuzzing_helper -o \"{output_dir}\" -a \"{fuzzer_id}\" "
        f"-n symcc -- \"{concolic_bin}\"'"
    )
    print(cmd)
    print(f"[+] Launching {session_name} on core {core_id} -> {concolic_bin}")
    subprocess.run(cmd, shell=True, check=False)

def launch_libfuzzer(core_id, input_dir, cluster_dir, stats_file, target, timeout, session_name, dictionary):
    exact_artifact_path = os.path.join(cluster_dir, "crash")
    dict_arg = f"-dict=\"{dictionary}\"" if dictionary else ""

    cmd = (
        f"screen -dmS {session_name} "
        f"bash -lc 'taskset -c {core_id} timeout -s INT {timeout} "
        f"{target} {input_dir} -exact_artifact_path=\"{exact_artifact_path}\" "
        f"{dict_arg} -ignore_crashes=1 -print_final_stats=1 "
        f"2>\"{stats_file}\"'"
    )
    print(f"[+] Launching {session_name} on core {core_id} -> {target}")
    print(cmd)
    subprocess.run(cmd, shell=True, check=False)

def write_manifset(output_dir):

    return

def read_manifest(config_path):
    
    return

def is_asan(binary_path):
    try:
        with open(binary_path, 'rb') as f:
            elffile = ELFFile(f)
            for section in elffile.iter_sections():
                if section.name in ('.symtab', '.dynsym'):
                    for sym in section.iter_symbols():
                        if sym.name == '__asan_init':
                            return True
    except FileNotFoundError:
        print(f"Warning: Binary '{binary_path}' not found during ASAN check.")
        return False
    except Exception as e:
        print(f"Warning: Could not read ELF symbols from '{binary_path}'. Error: {e}")
        return False
    return False



from time import sleep

def main():
    parser = argparse.ArgumentParser(description="Automated fuzzer launcher with multi-core support.")
    parser.add_argument("--fuzzer", required=True, choices=['honggfuzz', 'afl', 'aflpp', 'libfuzzer'], help="Fuzzer to use.")
    parser.add_argument("--target", required=True, help="Path to main fuzz target binary.")
    parser.add_argument("--asan-target", help="Path to ASAN variant binary (optional).")
    parser.add_argument("--input", required=True, help="Path to input corpus directory.")
    parser.add_argument("--output", required=True, help="Top-level output directory.")
    parser.add_argument("--timeout", default="12h", help="Timeout for each fuzzing job (e.g., 12h, 1d).")
    parser.add_argument("--clusters", type=int, default=10, help="Number of fuzzing clusters (c1..cN).")
    parser.add_argument("--jobs", type=int, default=2, help="Jobs per cluster (fuzz01..fuzzNN).")
    parser.add_argument("--start-core", type=int, default=0, help="Starting CPU core number (default 0).")
    parser.add_argument("--no-setup", action="store_true", help="Skip system setup (for testing).")
    parser.add_argument("--dict", help="Dictionary for fuzzing")
    parser.add_argument("--concolic", choices=['symcc', 'fuzzolic'], help="Run concolic execution with chosen tool")
    parser.add_argument("--concolic-bin", help="Path to symbolicaly instrumented binary")

    args = parser.parse_args()
    setup_system(args.no_setup)

    target1 = args.target
    target2 = args.asan_target if args.asan_target else target1

    total_cores = multiprocessing.cpu_count()
    core_id = args.start_core
    is_concolic = args.concolic in ['symcc', 'fuzzolic']
    if (is_concolic and not args.concolic_bin):
        raise Exception("Concolic execution enabled but no binary was provided")
    for cluster in range(1, args.clusters + 1):
        for job in range(1, args.jobs + 1):
            fuzz_name = f"fuzz{job:02d}"
            target = target1 if job % 2 != 0 else target2
            assigned_core = core_id % total_cores

            if args.fuzzer == 'honggfuzz':
                cluster_top_dir = os.path.join(args.output, f"c{cluster}")
                cluster_dir = os.path.join(cluster_top_dir, fuzz_name)
                crash_dir = os.path.join(cluster_dir, "crashes")
                make_dir(crash_dir)
                stats_file = os.path.join(cluster_dir, f"stats_{cluster}_{job}.txt")
                session_name = f"hf_c{cluster}_{fuzz_name}"
                launch_honggfuzz(
                    core_id=assigned_core,
                    input_dir=args.input,
                    cluster_dir=cluster_dir,
                    crash_dir=crash_dir,
                    stats_file=stats_file,
                    target=target,
                    timeout=args.timeout,
                    session_name=session_name,
                    dictionary=args.dict,
                    workspace=cluster_top_dir
                )
                core_id += 1
            elif args.fuzzer == 'libfuzzer':
                cluster_dir = os.path.join(args.output, f"c{cluster}", fuzz_name)
                corpus_dir = os.path.join(args.input, f"c{cluster}", fuzz_name)
                make_dir(cluster_dir)
                make_dir(corpus_dir)
                stats_file = os.path.join(cluster_dir, "fuzz.report")
                session_name = f"lf_c{cluster}_{fuzz_name}"
                launch_libfuzzer(
                    core_id=assigned_core,
                    input_dir=corpus_dir,
                    cluster_dir=cluster_dir,
                    stats_file=stats_file,
                    target=target,
                    timeout=args.timeout,
                    session_name=session_name,
                    dictionary=args.dict
                )
                core_id += 1
            elif args.fuzzer == 'afl' or args.fuzzer == 'aflpp':
                is_aflpp = args.fuzzer == 'aflpp'

                output_dir = os.path.join(args.output, f"c{cluster}")
                make_dir(output_dir)
                session_name = f"afl_c{cluster}_{fuzz_name}"
                is_main = (job == 1)
                launch_afl(
                    core_id=assigned_core,
                    input_dir=args.input,
                    output_dir=output_dir,
                    target=target,
                    timeout=args.timeout,
                    session_name=session_name,
                    dictionary=args.dict,
                    is_main=is_main,
                    is_aflpp=is_aflpp,
                )
                core_id += 1
            if args.concolic == 'symcc' and args.fuzzer in ['afl','aflpp'] and job == args.jobs:
                sleep(1)
                session_name = f"afl_c{cluster}_symcc"
                output_dir = os.path.join(args.output, f"c{cluster}")
                launch_symcc(
                    core_id=core_id,
                    fuzzer_id=f"fuzz{job:02d}",
                    concolic_bin=args.concolic_bin,
                    session_name=session_name,
                    timeout=args.timeout,
                    output_dir=output_dir
                )
                core_id += 1

    print("\n[*] All fuzzing jobs launched in screen sessions.")
    print("    List sessions with:  screen -ls")
    print("    Attach with:         screen -r <session_name>")


if __name__ == "__main__":
    main()
