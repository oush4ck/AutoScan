#!/bin/bash

clear
sudo apt install git -y
echo -e "\n\n\e[0;34m ACTUALIZANDO...\e[0;37m \n"
git clone https://github.com/anmh4ck2/AutoScan.git
if [[ -s AutoScan/autoscan.py ]];then
cd AutoScan
cp -r -f * .. > temp
cd ..
rm -rf  AutoScan >> temp
rm temp
chmod +x autoscan.py
python3 -m pip install --upgrade -r requirements.txt
echo -e "\n\n\e[0;32m ACTUALIZACION FINALIZADA CON ÉXITO !\n\n"
fi
