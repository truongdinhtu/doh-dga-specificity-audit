# using built-in modules
import random

#num_lines_in = 24000 # number of lines to read
num_lines_in = 28800 # number of lines to read, == 16000 + 800*4*4
#num_lines_in = 32000 # number of lines to read == 16000 + 1000*4*4
num_lines_in = 288 # test value, remove 00 from line_stop

# https://stackoverflow.com/questions/1767513/how-to-read-first-n-lines-of-a-file
#with open("tranco_N3NGW.csv", 'r') as input_csv:
with open("tranco_KJYKW.csv", 'r') as input_csv: # 11/02
    domains = [line.split(sep=",")[1] for (i, line) in enumerate(input_csv) if i < num_lines_in]
#print(len(domains))
#print(domains[:10])
random.seed(42)
random.shuffle(domains)

def write_csv(i, line_start, line_stop):
    with open(f"{i}.csv", 'w', newline="\n") as output_csv:
        #print(*domains[line_start:line_start+line_stop], sep="", end="", file=output_csv)
        output_csv.writelines(domains[line_start:line_start+line_stop])
    line_start += line_stop
    i += 1
    
    return i, line_start

num_doh_resolvers = 4
i = 0
line_start = 0

# firefox
for r in range(0,num_doh_resolvers):
    i, line_start = write_csv(i, line_start, 600)
    i, line_start = write_csv(i, line_start, 600)
    i, line_start = write_csv(i, line_start, 200)
    i, line_start = write_csv(i, line_start, 600)

# chrome
for r in range(0,num_doh_resolvers):
    i, line_start = write_csv(i, line_start, 700)
    i, line_start = write_csv(i, line_start, 700)
    i, line_start = write_csv(i, line_start, 600)

# doh_lookup_utils
for r in range(0,num_doh_resolvers):
    i, line_start = write_csv(i, line_start, 800)
    i, line_start = write_csv(i, line_start, 800)
    i, line_start = write_csv(i, line_start, 800)
    i, line_start = write_csv(i, line_start, 800)
