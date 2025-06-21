# Steganography Tool for Image/File Hiding

A Python GUI tool that allows embedding and extracting hidden text/data inside images using LSB-based steganography.

## Tools Used
- Python
- PIL (Pillow)
- Stepic
- Tkinter

## Features
- Hide text messages inside PNG/BMP images using LSB
- Extract hidden data from stego-images
- Simple drag-and-drop interface
- Supports file saving and preview

## Installation
```bash
git clone https://github.com/YamunaPechetti/Steganography-Project.git
cd steganography-tool
pip install -r requirements.txt
```
## Usage
- Select an image (.png or .bmp)
- Type your secret message
- Click Hide Message → Save new image
- To extract → Load stego-image → Click Show Message

## Supported Formats
- PNG
- BMP
