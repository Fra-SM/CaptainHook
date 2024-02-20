import frida
import sys
import argparse
from rich.console import Console
import codecs
import art
import subprocess
import re
import csv

# list of files containing instrumentation scripts grouped by category
hooks_files = [
               'stalker.ts', #includes memfing, cpufing, tabdescr and traps
               'stalling.ts',
               'timing.ts',
               'wmi.ts',
               'sysenv.ts',
               'geofencing.ts',
               'humint.ts',
               'registry.ts', #includes emulation checks
               'drivers.ts',
               'services.ts',
               'processes.ts', #includes emulation checks
               'procenv.ts',
               'exceptions.ts',
               'filesystem.ts',
               'others.ts',
               'memfing.ts'
]

# color mappings for pretty output
techniques_colors = {
               'Memory Fingerprinting': 1,
               'Stalling': 2,
               'Timing': 3, 
               'WMI': 4, 
               'System Environment': 5,
               'Human Interaction': 6,
               'Registry': 7,
               'Drivers': 8,
               'Services': 9,
               'Processes': 10,
               'Process Environment': 11,
               'Exception Handling': 12,
               'Emulation': 13,
               'Filesystem': 14,
               'Others': 15,
               'Geofencing': 79,
               'CPU Fingerprinting': 122,
               'Table Descriptors': 129,
               'Traps': 177
}

def update_detection_data(data):
    # Extract relevant information from the message
    technique_family = re.sub('[\[\]]', '', data.split(']')[0])
    technique_name = data.split('] ')[1].split(' ')[0]
    notes = data.split(' - ')[-1] if ' - ' in data else None

    # Read existing data from the CSV file
    existing_data = []
    try:
        with open(f'{args.save}.csv', mode='r') as file:
            reader = csv.DictReader(file, fieldnames=['Family', 'Name', 'Detections', 'Notes', 'Packers'])
            existing_data = list(reader)
    except FileNotFoundError:
        pass  # If the file doesn't exist, it will be created later

    technique_exists = any(item['Name'] == technique_name for item in existing_data)

    # Update existing data or add a new row
    if technique_exists:
        for item in existing_data:
            if item['Name'] == technique_name:
                # If notes are different, update both notes and number_of_detections
                if notes != None:
                  if notes not in item['Notes']:
                      item['Notes'] = item['Notes'] + ' - ' + notes
                      item['Detections'] = str(int(item['Detections']) + 1)
                # If notes are the same, only update the number_of_detections
                else:
                    item['Detections'] = str(int(item['Detections']) + 1)
    else:
        # Add a new row to the data
        new_row = {
            'Family': technique_family,
            'Name': technique_name,
            'Detections': '1',
            'Notes': notes,
            'Packers': args.save.lower().split('/')[-1]
        }
        existing_data.append(new_row)

    # Write the updated data back to the CSV file
    with open(f'{args.save}.csv', mode='w', newline='') as file:
        fieldnames = ['Family', 'Name', 'Detections', 'Notes', 'Packers']
        writer = csv.DictWriter(file, fieldnames=fieldnames)

        writer.writerows(existing_data)


def on_message(message, data):
    '''Callback to receive and log messages from Frida server'''

    if message['type'] == 'send':
      technique_family = re.sub('[\[\]]', '', message['payload'].split(']')[0])
      console.print(message['payload'], style=f'color({techniques_colors[technique_family]})')
      if (args.save != None):
        update_detection_data(message['payload'])
    else:
      print("[on_message] message:", message, "data:", data)

def load_hooks(session):
    '''Injects JS scripts into the newly spawned process'''

    for i in range(0, len(hooks_files)):
      try:
        with codecs.open(f'__handlers__/{hooks_files[i]}', 'r', 'utf-8') as f:
          source = f.read()

        script = session.create_script(source)
        script.on("message", on_message)
        script.load()
      except:
        console.log(f'Failed to load {hooks_files[i]}')
        pass

def remote_instrumentation(program, host, port):
    '''
    Spawns and instruments a process remotely

    For this to work, a frida-server binary matching Frida's version number 
    (current version: 16.1.4) must be installed and running on the remote
    system. Binaries can be found at https://github.com/frida/frida/releases
    To start the remote server, run: ./frida-server-YOUR_FILENAME -l 0.0.0.0
    On the client machine, instead, run the following command: 
    python3 shook.py -f FILEPATH remote SERVER_IP 27042
    27042 is the server's default listening port.
    Make sure the input file path matches the server directory path.
    '''

    try:
      device = frida.get_device_manager().add_remote_device(f'{host}:{port}')
      print(device)
      pid = device.spawn(program)
      session = device.attach(pid)
      session.enable_child_gating()
    except Exception as error:
      console.log(f'[red1]Error during remote process spawning! Check the host, port and file path')
      console.log(error)
      sys.exit(-1)
      
    load_hooks(session=session)
    device.resume(pid)
    print('Press CTRL-C to stop execution.')
    sys.stdin.read()
    session.detach()

def local_instrumentation(program):
    '''Spawns and instruments a process locally'''

    try:
      device = frida.get_local_device()
      pid = device.spawn(program)
      session = device.attach(pid)
      session.enable_child_gating()
    except Exception as error:
      console.log(f'[red1]Error during local process spawning! File \'{program}\' could not be opened')
      console.log(error)
      sys.exit(-1)
      
    load_hooks(session=session)
    device.resume(pid)
    print('Press CTRL-C to stop the execution.')
    sys.stdin.read()
    session.detach()


if __name__ == "__main__":
    console = Console()

    parser = argparse.ArgumentParser(prog='SHook!',
                                     description='Run a program with a bunch of hooks')

    parser.add_argument('-f', '--program', required=True, help='the path to the program you want to instrument')
    parser.add_argument('-s', '--save', required=False, help='name of the file you want to save results to')
    
    subparsers = parser.add_subparsers(title='subcommands', dest='subcommand')
    remote_parser = subparsers.add_parser('remote', help='remote instrumentation option, use -h for additional help')
    remote_parser.add_argument('host', metavar='IP', help='target host IP address')
    remote_parser.add_argument('port', metavar='port', help='target port')

    args = parser.parse_args()
    
    textArt = art.text2art('SHook!')
    subprocess.run(["lolcat -p 2"], shell=True, input=textArt, text=True)

    if (args.save != None):
       with open(f'{args.save}.csv', mode='w') as f:
          writer = csv.DictWriter(f, fieldnames=['Family', 'Name', 'Detections', 'Notes', 'Packers'])
          writer.writeheader()

    if args.subcommand == 'remote':
       remote_instrumentation(args.program, args.host, args.port)
    else:
       local_instrumentation(args.program)