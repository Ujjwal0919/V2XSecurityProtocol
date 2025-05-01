#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Import required libraries
import gpiod
import serial
import time

class sx126x:
    # GPIO Configuration
    GPIOCHIP = 0  # Default gpiochip for Raspberry Pi
    M0_LINE = 22  # GPIO pin for M0 control
    M1_LINE = 27  # GPIO pin for M1 control

    # LoRa Module Configuration Registers
    cfg_reg = [0xC2,0x00,0x09,0x00,0x00,0x00,0x62,0x00,0x12,0x43,0x00,0x00]
    get_reg = bytes(12)

    # Default Module Parameters
    rssi = False
    addr = 65535
    serial_n = ""
    addr_temp = 0

    # Frequency Configuration
    start_freq = 850  # Starting frequency in MHz
    offset_freq = 18  # Frequency offset

    # UART Baudrate Constants
    SX126X_UART_BAUDRATE_1200 = 0x00
    SX126X_UART_BAUDRATE_2400 = 0x20
    SX126X_UART_BAUDRATE_4800 = 0x40
    SX126X_UART_BAUDRATE_9600 = 0x60
    SX126X_UART_BAUDRATE_19200 = 0x80
    SX126X_UART_BAUDRATE_38400 = 0xA0
    SX126X_UART_BAUDRATE_57600 = 0xC0
    SX126X_UART_BAUDRATE_115200 = 0xE0

    # Package Size Constants
    SX126X_PACKAGE_SIZE_240_BYTE = 0x00
    SX126X_PACKAGE_SIZE_128_BYTE = 0x40
    SX126X_PACKAGE_SIZE_64_BYTE = 0x80
    SX126X_PACKAGE_SIZE_32_BYTE = 0xC0

    # Power Level Constants
    SX126X_Power_22dBm = 0x00
    SX126X_Power_17dBm = 0x01
    SX126X_Power_13dBm = 0x02
    SX126X_Power_10dBm = 0x03

    # Air Speed Mapping Dictionary
    lora_air_speed_dic = {
        1200: 0x01,
        2400: 0x02,
        4800: 0x03,
        9600: 0x04,
        19200: 0x05,
        38400: 0x06,
        62500: 0x07
    }

    # Power Level Mapping Dictionary
    lora_power_dic = {
        22: 0x00,
        17: 0x01,
        13: 0x02,
        10: 0x03
    }

    # Buffer Size Mapping Dictionary
    lora_buffer_size_dic = {
        240: SX126X_PACKAGE_SIZE_240_BYTE,
        128: SX126X_PACKAGE_SIZE_128_BYTE,
        64: SX126X_PACKAGE_SIZE_64_BYTE,
        32: SX126X_PACKAGE_SIZE_32_BYTE
    }

    def __init__(self, serial_num, freq, addr, power, rssi, 
                 air_speed=2400, net_id=0, buffer_size=240, 
                 crypt=0, relay=False, lbt=False, wor=False):
        """
        Initialize LoRa module with specified parameters
        
        Args:
            serial_num (str): Serial port name
            freq (int): Frequency in MHz
            addr (int): Node address
            power (int): Transmission power in dBm
            rssi (bool): Enable/disable RSSI reporting
            air_speed (int, optional): Air transmission speed. Defaults to 2400.
            net_id (int, optional): Network ID. Defaults to 0.
            buffer_size (int, optional): Buffer size. Defaults to 240.
            crypt (int, optional): Encryption key. Defaults to 0.
            relay (bool, optional): Enable relay mode. Defaults to False.
            lbt (bool, optional): Listen Before Talk. Defaults to False.
            wor (bool, optional): Wake on Radio. Defaults to False.
        """
        # Store module parameters
        self.rssi = rssi
        self.addr = addr
        self.freq = freq
        self.serial_n = serial_num
        self.power = power

        # Initialize GPIO using gpiod
        self.chip = gpiod.Chip(f'gpiochip{self.GPIOCHIP}')
        self.m0_line = self.chip.get_line(self.M0_LINE)
        self.m1_line = self.chip.get_line(self.M1_LINE)

        # Configure GPIO lines as output
        self.m0_line.request(consumer='sx126x_m0', type=gpiod.LINE_REQ_DIR_OUT)
        self.m1_line.request(consumer='sx126x_m1', type=gpiod.LINE_REQ_DIR_OUT)

        # Set initial GPIO states
        self.m0_line.set_value(0)
        self.m1_line.set_value(1)

        # Open serial connection
        self.ser = serial.Serial(serial_num, 9600)
        self.ser.flushInput()

        # Configure module settings
        self.set(freq, addr, power, rssi, air_speed, net_id, 
                 buffer_size, crypt, relay, lbt, wor)

    def __del__(self):
        """
        Cleanup GPIO resources when object is deleted
        """
        if hasattr(self, 'chip'):
            self.chip.close()

    def set(self, freq, addr, power, rssi, air_speed=2400,
            net_id=0, buffer_size=240, crypt=0,
            relay=False, lbt=False, wor=False):
        """
        Configure LoRa module settings
        
        Args: Same as __init__
        """
        # Prepare module for configuration
        self.m0_line.set_value(0)
        self.m1_line.set_value(1)
        time.sleep(0.1)

        # Calculate frequency parameters
        if freq > 850:
            freq_temp = freq - 850
            self.start_freq = 850
            self.offset_freq = freq_temp
        elif freq > 410:
            freq_temp = freq - 410
            self.start_freq = 410
            self.offset_freq = freq_temp
        
        # Validate and map air speed
        air_speed_temp = self.lora_air_speed_dic.get(air_speed, 0x02)
        
        # Validate and map buffer size
        buffer_size_temp = self.lora_buffer_size_dic.get(buffer_size, 0x00)
        
        # Validate and map power
        power_temp = self.lora_power_dic.get(power, 0x00)

        # Configure RSSI
        rssi_temp = 0x80 if rssi else 0x00

        # Prepare encryption
        l_crypt = crypt & 0xff
        h_crypt = crypt >> 8 & 0xff

        # Configure module registers based on relay mode
        if not relay:
            # Standard node configuration
            self.cfg_reg[3] = addr >> 8 & 0xff  # High address byte
            self.cfg_reg[4] = addr & 0xff       # Low address byte
            self.cfg_reg[5] = net_id & 0xff     # Network ID
            self.cfg_reg[6] = self.SX126X_UART_BAUDRATE_9600 + air_speed_temp
            self.cfg_reg[7] = buffer_size_temp + power_temp + 0x20
            self.cfg_reg[8] = freq_temp
            self.cfg_reg[9] = 0x43 + rssi_temp
            self.cfg_reg[10] = h_crypt
            self.cfg_reg[11] = l_crypt
        else:
            # Relay mode configuration
            self.cfg_reg[3] = 0x01
            self.cfg_reg[4] = 0x02
            self.cfg_reg[5] = 0x03
            self.cfg_reg[6] = self.SX126X_UART_BAUDRATE_9600 + air_speed_temp
            self.cfg_reg[7] = buffer_size_temp + power_temp + 0x20
            self.cfg_reg[8] = freq_temp
            self.cfg_reg[9] = 0x03 + rssi_temp
            self.cfg_reg[10] = h_crypt
            self.cfg_reg[11] = l_crypt

        # Send configuration
        self.ser.flushInput()
        for i in range(2):
            self.ser.write(bytes(self.cfg_reg))
            r_buff = 0
            time.sleep(0.2)
            if self.ser.inWaiting() > 0:
                time.sleep(0.1)
                r_buff = self.ser.read(self.ser.inWaiting())
                if r_buff[0] == 0xC1:
                    break
            else:
                print("setting fail, setting again")
                self.ser.flushInput()
                time.sleep(0.2)
                if i == 1:
                    print("setting fail, Press Esc to Exit and run again")

        # Set module to normal operation mode
        self.m0_line.set_value(0)
        self.m1_line.set_value(0)
        time.sleep(0.1)

    def send(self, data):
        """
        Send data through LoRa module
        
        Args:
            data (bytes): Data to be transmitted
        """
        self.m1_line.set_value(0)
        self.m0_line.set_value(0)
        time.sleep(0.1)

        self.ser.write(data)
        time.sleep(0.1)

    def receive(self):
        """
        Receive and process incoming data
        """
        if self.ser.inWaiting() > 0:
            time.sleep(0.5)
            r_buff = self.ser.read(self.ser.inWaiting())

            # Print received message details
            print(f"receive message from node address with frequence \033[1;32m {(r_buff[0]<<8)+r_buff[1]},{r_buff[2]+self.start_freq}.125MHz\033[0m")
            print(f"message is {str(r_buff[3:-1])}")
            
            # Print RSSI if enabled
            if self.rssi:
                print(f"the packet rssi value: -{256-r_buff[-1:][0]}dBm")
                self.get_channel_rssi()

    def get_channel_rssi(self):
        """
        Get channel RSSI (Received Signal Strength Indicator)
        """
        self.m1_line.set_value(0)
        self.m0_line.set_value(0)
        time.sleep(0.1)
        self.ser.flushInput()
        self.ser.write(bytes([0xC0,0xC1,0xC2,0xC3,0x00,0x02]))
        time.sleep(0.5)
        re_temp = bytes(5)
        if self.ser.inWaiting() > 0:
            time.sleep(0.1)
            re_temp = self.ser.read(self.ser.inWaiting())
        if re_temp[0] == 0xC1 and re_temp[1] == 0x00 and re_temp[2] == 0x02:
            print(f"the current noise rssi value: -{256-re_temp[3]}dBm")
        else:
            print("receive rssi value fail")