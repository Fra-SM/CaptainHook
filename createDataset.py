import pandas as pd
import os
import argparse

def merge_and_update_detections(file_paths):
    result_df = pd.DataFrame(columns=['Family', 'Name', 'Detections', 'Notes', 'Packers'])

    for file_path in file_paths:
        # Read the CSV file
        df = pd.read_csv(os.curdir + '/PackersThesisResults/' + file_path, on_bad_lines='warn')
        df.drop(columns="Notes", inplace=True)
        if args.aggregated == False:
            df.drop(columns="Packers", inplace=True)
        
        #result_df = result_df._append(df, ignore_index=True)
        result_df = pd.concat([result_df, df], ignore_index=True)
        if args.aggregated:   
            result_df = result_df.groupby(['Family', 'Name'], as_index=False).agg({
                                        'Packers': lambda x: ', '.join(map(str, x)), 'Detections': 'sum'
            })
            
    if args.aggregated:
        return result_df
    else:
        #this returns a result sheet without packer names where "detections" represents the number of packers using the technique
        return result_df.groupby(['Family', 'Name'], as_index=False)['Detections'].count()
     
file_paths = os.listdir(os.curdir + '/PackersThesisResults')

parser = argparse.ArgumentParser(prog='createDataset')

parser.add_argument('-a', '--aggregated', required=False, action='store_true', help='log packer names too')
args = parser.parse_args()

result_dataset = merge_and_update_detections(file_paths)

if args.aggregated == True:
    result_dataset.to_csv("result_dataset_with_packers.csv", index=False)
else:
    result_dataset.to_csv("result_dataset.csv", index=False)

