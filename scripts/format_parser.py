
import os
import glob

path = "/Users/Amine/Desktop/Imperial College - CS/Spring term/Msc Project/batch_sample/"

for filename in glob.iglob('/Users/Amine/Desktop/Imperial College - CS/Spring term/Msc Project/batch_sample/*'):
     #print(str(filename.replace(path,"")))
     f = open(filename)
     cell_time_and_dir = f.read().split()
     print(cell_time_and_dir)
     break
