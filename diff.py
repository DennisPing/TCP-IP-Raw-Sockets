import os
import argparse
import subprocess

def main():
    parser = argparse.ArgumentParser(
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument("file1", type=str, help="First file to compare")
    parser.add_argument("file2", type=str, help="Second file to compare")
    args = parser.parse_args()

    file1: str = args.file1
    file2: str = args.file2

    if not os.path.isfile(file1):
        print(f"{file1} does not exist")
        return 1
    if not os.path.isfile(file2):
        print(f"{file2} does not exist")
        return 1

    output = subprocess.run(['diff', file1, file2], capture_output=True)
    decoded = output.stdout.decode('utf-8')
    if decoded:
        print(decoded)
    else:
        print("The two files are identical")

    size1 = os.path.getsize(file1)
    size2 = os.path.getsize(file2)
    print(f"{file1}: {size1} bytes\n{file2}: {size2} bytes")

if __name__ == "__main__":
    main()