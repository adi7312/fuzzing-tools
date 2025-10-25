import subprocess, datetime
from pathlib import Path
from FTB.ProgramConfiguration import ProgramConfiguration
from FTB.Signatures.CrashInfo import CrashInfo
from Collector.Collector import Collector

collector = Collector()
reported_crashes = {}

def send_crash(input_file: Path, binary: str, config: ProgramConfiguration, llvm_instr=False):
    if input_file.is_file():
        crashInfo = None
        if llvm_instr:
            result = subprocess.run([binary, str(input_file)], stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        else:
            with input_file.open("rb") as f:
                result = subprocess.run([binary], stdin=f, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        try:
            stderr = result.stderr.decode(errors='replace').splitlines()
            stdout = result.stdout.decode(errors='replace').splitlines()
            crashInfo = CrashInfo.fromRawCrashData(stdout, stderr, config)
        except Exception as e:
            print(f"Error processing crash: {str(e)}")
            return
            
        if crashInfo:
            try:
                collector.submit(crashInfo)
            except Exception as e:
                print(f"[!][{datetime.datetime.now()}] Error submitting crash: {e}")


def traverse_crash_dir(path: Path, binary: str, fuzzer_id: int, fuzzer_name: str, campaign_id: int, llvm_instr=False):
    for file in path.iterdir():
        if not reported_crashes.get(file) and file.name != "README.txt" and file.name[-6:] != 'report':
            print(f"[*][{datetime.datetime.now()}] Crash detected: {file}")
            reported_crashes[file] = True
            config = ProgramConfiguration.fromBinary(binary)
            config.addMetadata({\
                    "campaign_id":campaign_id,
                    "fuzzer_id":fuzzer_id,
                    "fuzzer_name":fuzzer_name,
                    "hex_crash_data":file.read_bytes().hex()
                }
            )
            send_crash(file, binary, config, llvm_instr=llvm_instr)
            print(f"[+][{datetime.datetime.now()}] Crash sent from {campaign_id}/{fuzzer_id} to FuzzManager!")


def beacon(out_dir: str, binary: str, cid_start=1, cid_end=10, fuzz_start=1, fuzz_end=2, llvm_instr=False, is_libfuzzer=False):
    for cid in range(cid_start,cid_end+1):
        for i in range(fuzz_start,fuzz_end+1):
            if (not is_libfuzzer):
                crash_dir = Path(f"{out_dir}/{f'c{cid}'}/fuzz{i:02d}/crashes")
            else:
                crash_dir = Path(f"{out_dir}/{f'c{cid}'}/fuzz{i:02d}/")
            traverse_crash_dir(crash_dir, binary, i, binary, cid, llvm_instr=llvm_instr) 


from time import sleep
import click

@click.command()
@click.argument('out', type=click.Path(exists=True, file_okay=False))
@click.option("--binary", "-b", required=True, help="Path to ASAN binary", type=click.Path(exists=True))
@click.option("--interval", "-t", default=10, help="Polling interval in seconds")
@click.option("--llvm-instr", is_flag=True, help="Run binary with file as argument instead of stdin")
@click.option("--is-libfuzzer", is_flag=True, help="Is binary a libfuzzer binary?")
def main(out, binary, interval, llvm_instr, is_libfuzzer):
    print(f"[*][{datetime.datetime.now()}] FuzzManager client started...")
    try:
        while True:
            beacon(out, binary, llvm_instr=llvm_instr, is_libfuzzer=is_libfuzzer)
            sleep(interval)
    except KeyboardInterrupt:
        print(f"[!][{datetime.datetime.now()}] Interrupted by user. Exiting.")


main()
