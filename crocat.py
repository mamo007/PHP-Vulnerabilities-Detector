import sys
import argparse
import os
import subprocess
from detection import *
if __name__ == "__main__":
    # For colors in Windows
    if os.name == 'nt':
        subprocess.call('', shell=True)

    parser = argparse.ArgumentParser()
    parser.add_argument('--dir', action='store', dest='dir', help="Directory to analyse")
    parser.add_argument('--plain', action='store_true', dest='plain', help="No color in output")
    results = parser.parse_args()

    if results.dir is not None:
        # since we browse files recursively,
        # we need to set an higher threshold
        print(
        """
           
.o oOOOOOOOo                                            OOOOOO
    Ob.OOOOOOOo  OOOo.      oOOo.                      .adOOOOOOO
    OboO"""""""""""".OOo. .oOOOOOo.    OOOo.oOOOOOo..""""""""'OO
    OOP.oOOOOOOOOOOO "POOOOOOOOOOOo.   `"OOOOOOOOOP,OOOOOOOOOOOB'
    `O'OOOO'     `OOOOo"OOOOOOOOOOO` .adOOOOOOOOO"oOOO'    `OOOOo
    .OOOO'            `OOOOOOOOOOOOOOOOOOOOOOOOOO'            `OO
    OOOOO                 '"OOOOOOOOOOOOOOOO"`                oOO
   oOOOOOba.                .adOOOOOOOOOOba               .adOOOOo.
  oOOOOOOOOOOOOOba.    .adOOOOOOOOOO@^OOOOOOOba.     .adOOOOOOOOOOOO
 OOOOOOOOOOOOOOOOO.OOOOOOOOOOOOOO"`  '"OOOOOOOOOOOOO.OOOOOOOOOOOOOO
 "OOOO"       "YOoOOOOMOIONODOO"`  .   '"OOROAOPOEOOOoOY"     "OOO"
    Y           'OOOOOOOOOOOOOO: .oOOo. :OOOOOOOOOOO?'         :`
    :            .oO%OOOOOOOOOOo.OOOOOO.oOOOOOOOOOOOO         .
    .            oOOP"%OOOOOOOOoOOOOOOO?oOOOOO?OOOO"OOo
                 '%o  OOOO"%OOOO%"%OOOOO"OOOOOO"OOO': 
                      `$"  `OOOO' `O"Y ' `OOOO'  o             .
    .                  .     OP"          : o     .
　                                                                                                                                                                                                                                                                                                                                                                                                                                                                    
"""
																						"""
     /$$$$$$                       /$$$$$$              /$$          
    /$$__  $$                     /$$__  $$            | $$          
   | $$  \__/  /$$$$$$   /$$$$$$ | $$  \__/  /$$$$$$  /$$$$$$        
   | $$       /$$__  $$ /$$__  $$| $$       |____  $$|_  $$_/        
   | $$      | $$  \__/| $$  \ $$| $$        /$$$$$$$  | $$          
   | $$    $$| $$      | $$  | $$| $$    $$ /$$__  $$  | $$ /$$      
   |  $$$$$$/| $$      |  $$$$$$/|  $$$$$$/|  $$$$$$$  |  $$$$/      
    \______/ |__/       \______/  \______/  \_______/   \___/        
                                                                  
                                                                  
                                                                  
             """)
       
        print("\n{}Analyzing '{}' source code{}".format('' if results.plain else '\033[1m', results.dir, '' if results.plain else '\033[0m'))

        if os.path.isfile(results.dir):
            analysis(results.dirm, results.plain)
        else:
            recursive(results.dir, 0, results.plain)
        scanresults()

    else:
        parser.print_help()