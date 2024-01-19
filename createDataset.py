import pandas as pd
import os

def merge_and_update_detections(file_paths):
    result_df = pd.DataFrame(columns=['Family', 'Name', 'Detections', 'Notes', 'Packers'])

    for file_path in file_paths:
        # Read the CSV file
        df = pd.read_csv(os.curdir + '/PackersThesisResults/' + file_path, on_bad_lines='warn')
        df.drop(columns="Notes", inplace=True)

        #result_df = result_df._append(df, ignore_index=True)
        result_df = pd.concat([result_df, df], ignore_index=True)
        result_df = result_df.groupby(['Family', 'Name'], as_index=False).agg({
        'Packers': lambda x: ', '.join(map(str, x)), 'Detections': 'sum'
    })

    #this returns a result sheet without packer names where "detections" represents the number of packers using the technique
    #return result_df.groupby(['Family', 'Name'], as_index=False)['Detections'].count()
    return result_df

     
file_paths = os.listdir(os.curdir + '/PackersThesisResults')

result_dataset = merge_and_update_detections(file_paths)

#result_dataset.to_csv("result_dataset.csv", index=False)
result_dataset.to_csv("result_dataset_with_packers.csv", index=False)
