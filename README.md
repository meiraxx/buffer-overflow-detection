# Simple Buffer Overflow detection  

## Setup  
`python -m pip install --upgrade pip setuptools wheel`  
`pip install -r requirements.txt`  
`chmod +x test_tool.sh tool.py`  
  
## Test the tool  
You can run `python tool.py <file-name.json>` to test the file and get the output in the "outputs/" directory.  
You can also run `./test_tool.sh` and it will run through all the files in "public_basic_tests/" and "public_advanced_tests/" directory, generating its conclusions and writing them to the "outputs/" directory.   