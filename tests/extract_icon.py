import win32ui
import win32gui
import win32con
import win32api

import Image
import sys
import os

import tempfile
import shutil


def extract_icon(exefilename):
    """Get the first resource icon from win32 exefilename and returns it a s PNG bytes array"""
    ico_x = win32api.GetSystemMetrics(win32con.SM_CXICON)
    ico_y = win32api.GetSystemMetrics(win32con.SM_CYICON)

    large, small = win32gui.ExtractIconEx(exefilename,0)
    temp_dir = tempfile.mkdtemp()
    try:
        hdc = win32ui.CreateDCFromHandle( win32gui.GetDC(0) )
        hbmp = win32ui.CreateBitmap()
        hbmp.CreateCompatibleBitmap( hdc, ico_x, ico_x )
        hdc = hdc.CreateCompatibleDC()

        hdc.SelectObject( hbmp )
        hdc.DrawIcon( (0,0), large[0] )

        bmp_temp = os.path.join(temp_dir,"icon.bmp")
        hbmp.SaveBitmapFile(hdc,bmp_temp)

        im = Image.open(bmp_temp)
        png_temp = os.path.join(temp_dir,"icon.png")
        with open(png_temp,'wb') as png:
            im.save(png, "PNG")
            result = open(png_temp,'rb').read()

        return result
    finally:
        win32gui.DestroyIcon(small[0])
        win32gui.DestroyIcon(large[0])
        if os.path.isdir(temp_dir):
            shutil.rmtree(temp_dir)
