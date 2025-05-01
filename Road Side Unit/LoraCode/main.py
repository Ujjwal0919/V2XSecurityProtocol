#!/usr/bin/python
# -*- coding: UTF-8 -*-

import sys
import sx126x
import threading
import time
import select
import termios
import tty
from threading import Timer

# Store original terminal settings
old_settings = termios.tcgetattr(sys.stdin)
tty.setcbreak(sys.stdin.fileno())

def get_cpu_temp():
    """
    Read CPU temperature from system file
    
    Returns:
        float: CPU temperature in Celsius
    """
    try:
        with open("/sys/class/thermal/thermal_zone0/temp", "r") as tempFile:
            cpu_temp = tempFile.read().strip()
        return float(cpu_temp) / 1000
    except Exception as e:
        print(f"Error reading CPU temperature: {e}")
        return 0.0

# Initialize LoRa node with specific configuration
# Modify parameters as needed for your specific setup
node = sx126x.sx126x(
    serial_num="/dev/ttyAMA0",  # Serial port for LoRa module
    freq=868,                 # Frequency in MHz
    addr=0,                   # Node address
    power=22,                 # Transmission power in dBm
    rssi=True,                # Enable RSSI reporting
    air_speed=2400,           # Air transmission speed
    relay=False               # Disable relay mode
)

def send_deal():
    """
    Interactive method to send custom LoRa messages
    """
    get_rec = ""
    print("\nInput format: \033[1;32m0,868,Hello World\033[0m")
    print("(destination_address,frequency,message)")
    print("Press Enter key after input:", end='', flush=True)

    # Collect user input character by character
    while True:
        rec = sys.stdin.read(1)
        if rec is not None:
            if rec == '\x0a':  # Enter key
                break
            get_rec += rec
            sys.stdout.write(rec)
            sys.stdout.flush()

    # Parse input
    get_t = get_rec.split(",")

    try:
        # Calculate frequency offset
        offset_frequence = int(get_t[1]) - (850 if int(get_t[1]) > 850 else 410)

        # Prepare data packet
        data = (
            bytes([int(get_t[0])>>8]) +     # Destination high address byte
            bytes([int(get_t[0])&0xff]) +   # Destination low address byte
            bytes([offset_frequence]) +     # Frequency offset
            bytes([node.addr>>8]) +         # Source high address byte
            bytes([node.addr&0xff]) +       # Source low address byte
            bytes([node.offset_freq]) +     # Source frequency offset
            get_t[2].encode()               # Message payload
        )

        # Send the data
        node.send(data)

        # Clear input area
        print('\x1b[2A', end='\r')
        print(" "*200)
        print(" "*200)
        print(" "*200)
        print('\x1b[3A', end='\r')

    except Exception as e:
        print(f"Error sending message: {e}")

def send_cpu_continue(continue_or_not=True):
    """
    Periodically send CPU temperature
    
    Args:
        continue_or_not (bool): Whether to continue sending
    """
    global timer_task, seconds

    try:
        # Broadcast CPU temperature
        data = (
            bytes([255]) + bytes([255]) + bytes([18]) +  # Broadcast address
            bytes([255]) + bytes([255]) + bytes([12]) +  # Source address
            "CPU Temperature:".encode() +                # Message prefix
            str(get_cpu_temp()).encode() +               # Temperature value
            " C".encode()                                # Unit
        )
        node.send(data)
        time.sleep(0.2)

        if continue_or_not:
            timer_task = Timer(seconds, send_cpu_continue)
            timer_task.start()
        else:
            timer_task.cancel()

    except Exception as e:
        print(f"Error sending CPU temperature: {e}")

def main():
    """
    Main program loop for LoRa communication
    """
    try:
        time.sleep(1)
        print("Press \033[1;32mEsc\033[0m to exit")
        print("Press \033[1;32mi\033[0m   to send message")
        print("Press \033[1;32ms\033[0m   to send CPU temperature periodically")
        
        seconds = 10  # Periodic send interval
        
        while True:
            # Check for keyboard input
            if select.select([sys.stdin], [], [], 0) == ([sys.stdin], [], []):
                c = sys.stdin.read(1)

                # Exit
                if c == '\x1b': 
                    break
                
                # Send interactive message
                if c == '\x69':
                    send_deal()
                
                # Start periodic CPU temperature sending
                if c == '\x73':
                    print("Press \033[1;32mc\033[0m to stop periodic sending")
                    timer_task = Timer(seconds, send_cpu_continue)
                    timer_task.start()
                    
                    # Wait for stop command
                    while True:
                        if sys.stdin.read(1) == '\x63':
                            timer_task.cancel()
                            print('\x1b[1A', end='\r')
                            print(" "*100)
                            print('\x1b[1A', end='\r')
                            break

                sys.stdout.flush()
            
            # Continuously check for incoming messages
            node.receive()
    
    except KeyboardInterrupt:
        print("\nProgram terminated by user")
    except Exception as e:
        print(f"Unexpected error: {e}")
    finally:
        # Restore terminal settings
        termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old_settings)

if __name__ == "__main__":
    main()
