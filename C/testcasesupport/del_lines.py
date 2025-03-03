# del_lines.py

with open('./main_linux.txt','r') as r:
    lines=r.readlines()
with open('./main_linux1.txt','w') as w:
    for l in lines:
        if 'CWE121' in l:
          w.write(l) 
        if 'CWE124' in l:
          w.write(l) 
        if 'CWE126' in l:
          w.write(l)
        if 'CWE127' in l:
          w.write(l)
        if '#' in l:
          w.write(l)