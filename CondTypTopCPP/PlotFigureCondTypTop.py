import pandas as pd
import matplotlib.pyplot as plt
from matplotlib.backends.backend_pdf import PdfPages

# Read the .dat file
file_path = 'CondTypTopEval.dat'  # Update this with the actual path to the .dat file

# Read the .dat file into a DataFrame
df = pd.read_csv(file_path, sep='\t')

# Function to wrap long text in table cells
def wrap_text(text, width=25):
    return '\n'.join([text[i:i+width] for i in range(0, len(text), width)])

# Apply the text wrapping function to each cell in the DataFrame
wrapped_df = df.applymap(lambda x: wrap_text(str(x), width=15))  # Adjust the width accordingly

# Create a matplotlib figure with specific size (adjust to match the PDF width)
fig, ax = plt.subplots(figsize=(10, 6))  # Adjust figsize for better page fitting

# Hide the axes
ax.xaxis.set_visible(False)
ax.yaxis.set_visible(False)
ax.set_frame_on(False)

# Create a table with wrapped text
table = ax.table(cellText=wrapped_df.values, colLabels=wrapped_df.columns, cellLoc='center', loc='center')

# Adjust table layout to fit page width
table.auto_set_font_size(False)
table.set_fontsize(10)

# Adjust column widths to fit the page width
table.scale(2.5, 2.5)  # Scale to fit width (increase the first number to make it wider)
table.auto_set_column_width(col=list(range(len(df.columns))))

# Save the table as a PDF with a specific page size (to fit width)
pdf_file = 'output_table_CondTypTopEval.pdf'
with PdfPages(pdf_file) as pdf:
    fig.tight_layout()
    pdf.savefig(fig, bbox_inches='tight')

plt.close(fig)

print(f"Table has been fitted to the page width and saved to {pdf_file}")
