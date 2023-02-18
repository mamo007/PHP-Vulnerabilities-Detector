import sys
import argparse
import os
from detection import *
if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument('--dir', action='store', dest='dir', help="Directory to analyse")
    parser.add_argument('--plain', action='store_true', dest='plain', help="No color in output")
    results = parser.parse_args()

    if results.dir is not None:
        # since we browse files recursively,
        # we need to set an higher threshold
        print("""\




  /$$$$$$  /$$$$$$$$  /$$$$$$  /$$   /$$ /$$$$$$$  /$$$$$$$$       /$$$$$$$  /$$$$$$$$/$$    /$$  /$$$$$$  /$$        /$$$$$$  /$$$$$$$  /$$$$$$$$ /$$$$$$$ 
 /$$__  $$| $$_____/ /$$__  $$| $$  | $$| $$__  $$| $$_____/      | $$__  $$| $$_____/ $$   | $$ /$$__  $$| $$       /$$__  $$| $$__  $$| $$_____/| $$__  $$
| $$  \__/| $$      | $$  \__/| $$  | $$| $$  \ $$| $$            | $$  \ $$| $$     | $$   | $$| $$  \ $$| $$      | $$  \ $$| $$  \ $$| $$      | $$  \ $$
|  $$$$$$ | $$$$$   | $$      | $$  | $$| $$$$$$$/| $$$$$         | $$  | $$| $$$$$  |  $$ / $$/| $$  | $$| $$      | $$  | $$| $$$$$$$/| $$$$$   | $$$$$$$/
 \____  $$| $$__/   | $$      | $$  | $$| $$__  $$| $$__/         | $$  | $$| $$__/   \  $$ $$/ | $$  | $$| $$      | $$  | $$| $$____/ | $$__/   | $$__  $$
 /$$  \ $$| $$      | $$    $$| $$  | $$| $$  \ $$| $$            | $$  | $$| $$       \  $$$/  | $$  | $$| $$      | $$  | $$| $$      | $$      | $$  \ $$
|  $$$$$$/| $$$$$$$$|  $$$$$$/|  $$$$$$/| $$  | $$| $$$$$$$$      | $$$$$$$/| $$$$$$$$  \  $/   |  $$$$$$/| $$$$$$$$|  $$$$$$/| $$      | $$$$$$$$| $$  | $$
 \______/ |________/ \______/  \______/ |__/  |__/|________/      |_______/ |________/   \_/     \______/ |________/ \______/ |__/      |________/|__/  |__/
                                                                                                                                                            
                                                                                                                                                            
                                                                                                                                                            

                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        
                                                                                                                                                                                                                                                                                                                                
""")
     
        print("\n{}Analyzing '{}' source code{}".format('' if results.plain else '\033[1m', results.dir, '' if results.plain else '\033[0m'))

        if os.path.isfile(results.dir):
            analysis(results.dirm, results.plain)
        else:
            recursive(results.dir, 0, results.plain)
        scanresults()

    else:
        parser.print_help()
