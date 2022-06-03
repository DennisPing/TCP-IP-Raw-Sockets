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

    file1 = args.file1
    file2 = args.file2

    subprocess.run(['diff', file1, file2])

    size1 = os.path.getsize(file1)
    size2 = os.path.getsize(file2)
    print(f"{file1} = {size1} bytes\n{file2} = {size2} bytes")

if __name__ == "__main__":
    main()