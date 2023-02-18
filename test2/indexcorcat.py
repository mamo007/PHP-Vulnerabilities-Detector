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
        str11="""
            
  /$$$$$$                      /$$$$$$             /$$          
 /$$__  $$                    /$$__  $$           | $$          
| $$  \__/  /$$$$$$  /$$$$$$ | $$  \__/ /$$$$$$  /$$$$$$        
| $$       /$$__  $$/$$__  $$| $$      |____  $$|_  $$_/        
| $$      | $$  \__/ $$  \ $$| $$       /$$$$$$$  | $$          
| $$    $$| $$     | $$  | $$| $$    $$/$$__  $$  | $$ /$$      
|  $$$$$$/| $$     |  $$$$$$/|  $$$$$$/  $$$$$$$  |  $$$$/      
 \______/ |__/      \______/  \______/ \_______/   \___/        

             """
        str22= """
            
 (_＼ヽ
　 ＼＼ .Λ＿Λ.
　　 ＼(　ˇωˇ)　
　　　 >　⌒ヽ
　　　/ 　 へ＼
　　 /　　/　＼＼
　　 ﾚ　ノ　　 ヽ_つ
　                                                                                                                                                                                                                                                                                                                                                                                                                                                                    
"""
        def combineStr(str1, str2):
            l1 = str1.split('\n')
            l2 = str2.split('\n')
            for i in range(min(len(l1), len(l2))):
                print(l1[i]+'\t'+l2[i]); 
        combineStr(str11, str22)
        print("\n{}Analyzing '{}' source code{}".format('' if results.plain else '\033[1m', results.dir, '' if results.plain else '\033[0m'))

        if os.path.isfile(results.dir):
            analysis(results.dirm, results.plain)
        else:
            recursive(results.dir, 0, results.plain)
        scanresults()

    else:
        parser.print_help()
