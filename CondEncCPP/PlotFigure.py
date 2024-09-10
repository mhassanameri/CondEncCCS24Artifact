import argparse
import matplotlib.pyplot as plt
import numpy as np
from matplotlib.backends.backend_pdf import PdfPages
import webbrowser

# Function to read .dat file and return structured data
def read_dat_file(filename):
    data = np.loadtxt(filename, skiprows=10)  # Skip the first 10 rows (comments)
    return data

# Function to plot data from multiple files
def Plot_figure1a(data_list, file_names, title, pdf):
    fig, ax = plt.subplots()
    ax.set_yscale('log')

    # Loop over each dataset and plot
    for data, file_name in zip(data_list, file_names):
        L = data[:, 1]        # Maximum Length of Secret Message (L)
        Enc = data[:, 2]      # Regular Encryption Time (msec)
        CondEnc = data[:, 3]  # Conditional Encryption Time (msec)
        CondDec = data[:, 4]  # Conditional Decryption Time (msec)

        #         ax.plot(L, Enc, label=f'{file_name} - Enc', marker='o', linestyle='-', color='red')
        #         ax.plot(L, CondEnc, label=f'{file_name} - CondEnc', marker='x', linestyle='-', color='blue')
        if file_name.startswith("OPT"):

            if file_name[13] == "1":
                ax.plot(L, CondDec, label=f'T: {file_name[13]} - OPT-CondDec', marker='D', linestyle='--', color='red')
            elif file_name[13] == "2":
                ax.plot(L, CondDec, label=f'T: {file_name[13]} - OPT-CondDec', marker='o', linestyle='--', color='red')
            elif file_name[13] == "3":
                ax.plot(L, CondDec, label=f'T: {file_name[13]} - OPT-CondDec', marker='^', linestyle='--', color='red')
            elif file_name[13] == "4":
                ax.plot(L, CondDec, label=f'T: {file_name[13]} - OPT-CondDec', marker='s', linestyle='--', color='red')

        else:
            if file_name[9] == "1":
                ax.plot(L, CondDec, label=f'T: {file_name[9]} - Orig-CondDec', marker='D', linestyle='--', color='blue')
            elif file_name[9] == "2":
                ax.plot(L, CondDec, label=f'T: {file_name[9]} - Orig-CondDec', marker='o', linestyle='--', color='blue')
            elif file_name[9] == "3":
                ax.plot(L, CondDec, label=f'T: {file_name[9]} - Orig-CondDec', marker='^', linestyle='--', color='blue')
            elif file_name[9] == "4":
                ax.plot(L, CondDec, label=f'T: {file_name[9]} - Orig-CondDec', marker='s', linestyle='--', color='blue')

    ax.set_xlabel('Input Length (n)')
    ax.set_ylabel('Time (msec)')
    ax.set_title(title)
    ax.grid(True)

    # Adding a legend

    ax.legend(loc=(0, .3))

    # Save to PDF
    pdf.savefig(fig)
    plt.close()


def Plot_figure1b(data_list, file_names, title, pdf):
    fig, ax = plt.subplots()
    ax.set_yscale('log')

    # Loop over each dataset and plot
    for data, file_name in zip(data_list, file_names):
        T = data[:, 0]        # The Maximum Hamming Distance (T)
        L = data[:, 1]        # Maximum Length of Secret Message (L)
        Enc = data[:, 2]      # Regular Encryption Time (msec)
        CondEnc = data[:, 3]  # Conditional Encryption Time (msec)
        CondDec = data[:, 4]  # Conditional Decryption Time (msec)

        #         ax.plot(L, Enc, label=f'{file_name} - Enc', marker='o', linestyle='-', color='red')
        #         ax.plot(L, CondEnc, label=f'{file_name} - CondEnc', marker='x', linestyle='-', color='blue')
        if file_name.startswith("OPT"):

            if "8" in file_name:
                ax.plot(T, CondDec, label=f'n: 8 - OPT-CondDec', marker='D', linestyle='--', color='red')
            elif "16" in file_name:
                ax.plot(T, CondDec, label=f'n: 16 - OPT-CondDec', marker='o', linestyle='--', color='red')
            elif "32" in file_name:
                ax.plot(T, CondDec, label=f'n: 32 - OPT-CondDec', marker='^', linestyle='--', color='red')
            elif "64" in file_name:
                ax.plot(T, CondDec, label=f'n: 64 - OPT-CondDec', marker='s', linestyle='--', color='red')
            elif "128" in file_name:
                ax.plot(T, CondDec, label=f'n: 128 - OPT-CondDec', marker='s', linestyle='--', color='red')

        else:
            if "8" in file_name:
                ax.plot(T, CondDec, label=f'n: 8 - Orig-CondDec', marker='D', linestyle='--', color='blue')
            elif "16" in file_name:
                ax.plot(T, CondDec, label=f'n: 16 - Orig-CondDec', marker='o', linestyle='--', color='blue')
            elif "32" in file_name:
                ax.plot(T, CondDec, label=f'n: 32 - Orig-CondDec', marker='^', linestyle='--', color='blue')
            elif "64" in file_name:
                ax.plot(T, CondDec, label=f'n: 64 - Orig-CondDec', marker='s', linestyle='--', color='blue')
            elif "128" in file_name:
                ax.plot(T, CondDec, label=f'n: 128 - Orig-CondDec', marker='v', linestyle='--', color='blue')


    ax.set_xlabel('Input Length (n)')
    ax.set_ylabel('Time (msec)')
    ax.set_title(title)
    ax.grid(True)

    # Adding a legend
    ax.legend(loc=(0, .5))

    # Save to PDF
    pdf.savefig(fig)
    plt.close()

def Plot_figure1c(data_list, file_names, title, pdf):
    fig, ax = plt.subplots()
    ax.set_yscale('log')

    # Loop over each dataset and plot
    for data, file_name in zip(data_list, file_names):
        T = data[:, 0]        # The Maximum Hamming Distance (T)
        L = data[:, 1]        # Maximum Length of Secret Message (L)
        Enc = data[:, 2]      # Regular Encryption Time (msec)
        CondEnc = data[:, 3]  # Conditional Encryption Time (msec)
        CondDec = data[:, 4]  # Conditional Decryption Time (msec)

        #         ax.plot(L, Enc, label=f'{file_name} - Enc', marker='o', linestyle='-', color='red')
        #         ax.plot(L, CondEnc, label=f'{file_name} - CondEnc', marker='x', linestyle='-', color='blue')
        if "T1" in file_name:
            ax.plot(L, Enc, label=f'T: 1 -Enc', marker='D', linestyle='-', color='red')
            ax.plot(L, CondEnc, label=f'T: 1  -CondEnc', marker='D', linestyle='-', color='blue')
        elif "T2" in file_name:
            ax.plot(L, Enc, label=f'T: 2 -Enc', marker='o', linestyle='-', color='red')
            ax.plot(L, CondEnc, label=f'T: 2 -CondEnc', marker='o', linestyle='-', color='blue')
        elif "T3" in file_name:
            ax.plot(L, Enc, label=f'T: 3 -Enc', marker='v', linestyle='-', color='red')
            ax.plot(L, CondEnc, label=f'T: 3 -CondEnc', marker='v', linestyle='-', color='blue')
        elif "T4" in file_name:
            ax.plot(L, Enc, label=f'T: 4 -Enc', marker='s', linestyle='-', color='red')
            ax.plot(L, CondEnc, label=f'T: 4 -CondEnc', marker='s', linestyle='-', color='blue')


    ax.set_xlabel('Input Length (n)')
    ax.set_ylabel('Time (msec)')
    ax.set_title(title)
    ax.grid(True)

    # Adding a legend
    ax.legend(loc=(0, .5))

    # Save to PDF
    pdf.savefig(fig)
    plt.close()


# This function generates a pdf file which plots Figure 1a of the paper.
def generate_pdf_figure1a(dat_files, output_pdf):
    data_list = [read_dat_file(file) for file in dat_files]

    with PdfPages(output_pdf) as pdf:
        Plot_figure1a(data_list, dat_files, title="Conditional Encryption-CondDec Performance, for Hamming Distance at most T = {1,2,3.4}", pdf=pdf)


# This function generates a pdf file which plots Figure 1b of the paper.
def generate_pdf_figure1b(dat_files, output_pdf):
    data_list = [read_dat_file(file) for file in dat_files]

    with PdfPages(output_pdf) as pdf:
        Plot_figure1b(data_list, dat_files, title="Conditional Encryption-CondDec Performance, for Hamming Distance at most T = {1,2,3.4}", pdf=pdf)

# This function generates a pdf file which plots Figure 1c of the paper.

def generate_pdf_figure1c(dat_files, output_pdf):
    data_list = [read_dat_file(file) for file in dat_files]

    with PdfPages(output_pdf) as pdf:
        Plot_figure1c(data_list, dat_files, title="Conditional Encryption-Enc and CondEnc Performance Evaluation, for Hamming Distance at most T = {1,2,3.4}", pdf=pdf)




def main(FigureName):
    # print(f"Plotting{FigureName}")
    if FigureName == "Figure1a":
        dat_files1 = ['HDdataL_T1.dat', 'HDdataL_T2.dat', 'HDdataL_T3.dat', 'HDdataL_T4.dat',
                     'OPT_HDdataL_T1.dat', 'OPT_HDdataL_T2.dat', 'OPT_HDdataL_T3.dat', 'OPT_HDdataL_T4.dat']  # Replace with your actual .dat file names
        output_pdf1 = 'Figure1a.pdf'
        generate_pdf_figure1a(dat_files1, output_pdf1)
        webbrowser.open_new_tab(output_pdf1)
    elif FigureName == "Figure1b":
        dat_files2 = ['HDdataL8_T.dat', 'HDdataL16_T.dat', 'HDdataL32_T.dat', 'HDdataL64_T.dat', 'HDdataL128_T.dat',
                      'OPT_HDdataL8_T.dat', 'OPT_HDdataL16_T.dat', 'OPT_HDdataL32_T.dat', 'OPT_HDdataL64_T.dat', 'OPT_HDdataL128_T.dat']  # Replace with your actual .dat file names
        output_pdf2 = 'Figure1b.pdf'
        generate_pdf_figure1b(dat_files2, output_pdf2)
        webbrowser.open_new_tab(output_pdf2)
    elif FigureName == "Figure1c":
        dat_files3 = ['OPT_HDdataL_T1.dat', 'OPT_HDdataL_T2.dat', 'OPT_HDdataL_T3.dat', 'OPT_HDdataL_T4.dat']  # Replace with your actual .dat file names
        output_pdf3 = 'Figure1c.pdf'
        generate_pdf_figure1c(dat_files3, output_pdf3)
        webbrowser.open_new_tab(output_pdf3)




#Usge of this scrypt: To plot the desired figure we just need to execute the following command on terminal
#associated to the path that contains this script (e.g., /build/test). For example if we want ot plot
# ``Figure 1a'' of the paper, we can simply run the following command (after the test scripts are executed and the output
# .dat are generated):
# $ python3 ./PlotFigure.py Figure1a


if __name__ == "__main__":
    # Create the parser
    parser = argparse.ArgumentParser(description="Process the inputs.")

    # Add arguments
    parser.add_argument("name", type=str, help="Your name")

    # Parse arguments
    args = parser.parse_args()

    # Call the main function with parsed arguments
    main(args.name)

