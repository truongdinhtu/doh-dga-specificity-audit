import csv, sys

cols_L3 = ['%dir', 'flowInd', 'timeFirst', 'timeLast', 'duration', 'srcIP', 'srcPort', 'dstIP', 'dstPort', 'l4Proto', 'pktsSnt', 'l3BytesSnt', 'minL3PktSz', 'maxL3PktSz', 'avgL3PktSz', 'stdL3PktSz', 'varL3PktSz', 'skewL3PktSz', 'kurL3PktSz', 'minIAT', 'maxIAT', 'avgIAT', 'stdIAT', 'varIAT', 'skewIAT', 'kurIAT', 'pktps', 'bytps', 'pktAsm', 'bytAsm', 'ipMinTTL', 'ipMaxTTL', 'ipToS', 'tcpFlags', 'tcpCntF_S_R_P_A_U_E_C_FA_SA_RA_N_SF_SFR_RF_X']
cols_L7 = ['l7BytesSnt', 'minL7PktSz', 'maxL7PktSz', 'avgL7PktSz', 'stdL7PktSz', 'varL7PktSz', 'skewL7PktSz', 'kurL7PktSz', 'bytps', 'bytAsm']

with open(sys.argv[1], 'r', newline='') as csv_L3:
    with open(sys.argv[2], 'r', newline='') as csv_L7:
        # auto detect delimeter and lineterminator ...
        detected_dialect = csv.Sniffer().sniff(csv_L3.readline(), delimiters=["\t", ","])
        csv_L3.seek(0) # reset current position

        reader_L3 = csv.reader(csv_L3, detected_dialect)
        reader_L7 = csv.reader(csv_L7, detected_dialect)
        
        headers_L3 = next(reader_L3)
        headers_L7 = next(reader_L7)

        col_indices_L3 = [i for i,v in enumerate(headers_L3) if v in cols_L3]
        col_indices_L7 = [i for i,v in enumerate(headers_L7) if v in cols_L7]

        headers_L3 = [headers_L3[i] for i in col_indices_L3]
        headers_L7 = [headers_L7[i] for i in col_indices_L7]
        headers_L7[headers_L7.index("bytps")] = "L7bytps"
        headers_L7[headers_L7.index("bytAsm")] = "L7bytAsm"

        with open(sys.argv[1].replace("_L3", ""), 'w', newline='') as output_csv:
            writer = csv.writer(output_csv, detected_dialect)

            writer.writerow(headers_L3 + headers_L7)
            for row_L3, row_L7 in zip(reader_L3, reader_L7):
                writer.writerow([row_L3[i] for i in col_indices_L3] + [row_L7[i] for i in col_indices_L7])
                