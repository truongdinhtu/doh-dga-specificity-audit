# using built-in modules
import random

#domains_per_input = 96 # test value
domains_per_input = 4000

# qsnatch-50000.txt contains 361 invalid domains with "..", replace before parsing
for filename in ["bazarbackdoor_v3-20000.txt", "flubot_v4.8_202112.txt", "qsnatch-50000.txt", "zloader-50000.txt"]:
    with open(filename, 'r') as input_csv:
        #domains = [line for (i, line) in enumerate(input_csv) if i < num_lines_in]
        domains = input_csv.readlines()
    #print(len(domains))
    #print(domains[:10])
    random.seed(42)
    random.shuffle(domains)

    i = 0
    line_start = 0
    #lines_per_output = 6 # test value
    lines_per_output = 250 # number of lines per output
    while (line_start < domains_per_input):
        with open(f"{filename[:-4].replace('-', '_').split(sep='_')[0]}_{i}.csv", 'w', newline="\n") as output_csv:
            output_csv.writelines(domains[line_start:line_start+lines_per_output])
        line_start += lines_per_output
        i += 1
