Wi-Fi Scanner Tool
    
     A simple python based WiFI Scanner Tool for detecting and displaying details of nearby WiFi networks. This tool uses subprocess and pywifi library to capture and analyze WiFi providing information such as SSID, BSSID, and channel for each detected network.
   
Installation
   
   Clone the Repository:
   
   bash
   
git clone https://github.com/USERNAME/wifi-scanner.git cd wifi-scanner

Install Dependencies:

  bash

   Usage

   Set Your Network Interface to Monitor Mode:

Make sure your network interface is in monitor mode. You can use tools like airmon-ng to enable monitor mode:

bash

sudo airmon-ng start wlan0

Replace wlan0 with your network interface.

Run the Scanner:

bash

sudo python wifi_scanner.py wlan0mon

Replace wlan0mon with the monitor mode interface name.
