import paho.mqtt.client as mqtt
import tkinter as tk
from tkinter import ttk, messagebox
import threading

# MQTT settings
MQTT_BROKER = "localhost"  # Use localhost for the local broker
MQTT_PORT = 1883
MQTT_TOPIC = "iot/devices"
CLIENT_ID_PREFIX = "Device"

# IoT Device class
class IoTDevice:
    def __init__(self, device_id, device_type, owner):
        self.device_id = device_id
        self.device_type = device_type
        self.owner = owner
        self.is_active = False
        self.client = mqtt.Client(client_id=f"{CLIENT_ID_PREFIX}_{device_id}")  # Updated client initialization

        # Using updated callback API
        self.client.on_connect = self.on_connect
        self.client.on_message = self.on_message
        self.client.on_disconnect = self.on_disconnect

    def on_connect(self, client, userdata, flags, rc):
        if rc == 0:
            print(f"Device {self.device_id} connected successfully.")
            self.client.subscribe(f"{MQTT_TOPIC}/{self.device_id}/control")
        else:
            print(f"Failed to connect Device {self.device_id}, Return code: {rc}")

    def on_message(self, client, userdata, msg):
        command = msg.payload.decode()
        print(f"Received command: {command}")
        if command == "START":
            self.start_device()
        elif command == "STOP":
            self.stop_device()
        else:
            print(f"Device {self.device_id} received unrecognized command: {command}")

    def on_disconnect(self, client, userdata, rc):
        print(f"Device {self.device_id} disconnected.")

    def connect(self):
        self.client.connect(MQTT_BROKER, MQTT_PORT, 60)
        self.client.loop_start()

    def start_device(self):
        self.is_active = True
        print(f"Device {self.device_id} is now active.")

    def stop_device(self):
        self.is_active = False
        print(f"Device {self.device_id} is now stopped.")

# GUI Application
class IoTDeviceSimulator:
    def __init__(self, root):
        self.root = root
        self.root.title("IoT Device Management")
        self.devices = {}

        # Create the GUI layout
        self.create_widgets()

    def create_widgets(self):
        self.device_id_label = ttk.Label(self.root, text="Device ID:")
        self.device_id_label.grid(row=0, column=0, padx=10, pady=5)

        self.device_id_entry = ttk.Entry(self.root)
        self.device_id_entry.grid(row=0, column=1, padx=10, pady=5)

        self.device_type_label = ttk.Label(self.root, text="Device Type:")
        self.device_type_label.grid(row=1, column=0, padx=10, pady=5)

        self.device_type_combobox = ttk.Combobox(self.root, state="readonly")
        self.device_type_combobox['values'] = ('Sensor', 'Actuator', 'Gateway')
        self.device_type_combobox.grid(row=1, column=1, padx=10, pady=5)

        self.owner_label = ttk.Label(self.root, text="Owner (Ethereum Address):")
        self.owner_label.grid(row=2, column=0, padx=10, pady=5)

        self.owner_entry = ttk.Entry(self.root)
        self.owner_entry.grid(row=2, column=1, padx=10, pady=5)

        self.register_button = ttk.Button(self.root, text="Register Device", command=self.register_device)
        self.register_button.grid(row=3, column=0, columnspan=2, pady=10)

        self.status_label = ttk.Label(self.root, text="Device Status: Not Registered")
        self.status_label.grid(row=4, column=0, columnspan=2, pady=10)

        self.start_button = ttk.Button(self.root, text="Start Device", command=self.start_device, state=tk.DISABLED)
        self.start_button.grid(row=5, column=0, pady=5)

        self.stop_button = ttk.Button(self.root, text="Stop Device", command=self.stop_device, state=tk.DISABLED)
        self.stop_button.grid(row=5, column=1, pady=5)

        # Device List Label
        self.device_list_label = ttk.Label(self.root, text="Registered Devices:")
        self.device_list_label.grid(row=6, column=0, columnspan=2, pady=10)

        # Device Treeview to display devices
        self.device_tree = ttk.Treeview(self.root, columns=("Device ID", "Device Type", "Owner", "Status"), show="headings")
        self.device_tree.heading("Device ID", text="Device ID")
        self.device_tree.heading("Device Type", text="Device Type")
        self.device_tree.heading("Owner", text="Owner")
        self.device_tree.heading("Status", text="Status")
        self.device_tree.grid(row=7, column=0, columnspan=2, padx=10, pady=5)

        # Device selection in Treeview
        self.device_tree.bind("<<TreeviewSelect>>", self.on_device_select)

    def register_device(self):
        device_id = self.device_id_entry.get()
        device_type = self.device_type_combobox.get()
        owner = self.owner_entry.get()

        if not device_id or not device_type or not owner:
            messagebox.showerror("Error", "Please provide all device details.")
            return

        if device_id in self.devices:
            messagebox.showwarning("Warning", f"Device {device_id} is already registered.")
            return

        # Register the new device
        new_device = IoTDevice(device_id, device_type, owner)
        self.devices[device_id] = new_device
        new_device.connect()

        # Add to Treeview
        self.device_tree.insert("", "end", iid=device_id, values=(device_id, device_type, owner, "Inactive"))
        messagebox.showinfo("Device Registered", f"Device {device_id} has been registered.")
        self.device_id_entry.delete(0, tk.END)
        self.device_type_combobox.set('')
        self.owner_entry.delete(0, tk.END)

    def start_device(self):
        device_id = self.device_id_entry.get()  # Get device ID from entry field
        if device_id in self.devices:
            device = self.devices[device_id]
            if not device.is_active:
                device.start_device()
                print(f"Device {device_id} started.")  # Debugging line
                messagebox.showinfo("Device Started", f"Device {device_id} is now active!")
                self.status_label.config(text=f"Device {device_id} is Active")
                # Update device status in Treeview
                self.update_device_status(device_id, "Active")
            else:
                print(f"Device {device_id} is already active.")  # Debugging line
        else:
            messagebox.showerror("Error", "Device not found.")

    def stop_device(self):
        device_id = self.device_id_entry.get()  # Get device ID from entry field
        if device_id in self.devices:
            device = self.devices[device_id]
            if device.is_active:
                device.stop_device()
                messagebox.showinfo("Device Stopped", f"Device {device_id} is now stopped!")
                self.status_label.config(text=f"Device {device_id} is Inactive")
                # Update device status in Treeview
                self.update_device_status(device_id, "Inactive")
            else:
                print(f"Device {device_id} is already stopped.")  # Debugging line
        else:
            messagebox.showerror("Error", "Device not found.")

    def update_device_status(self, device_id, status):
        # Find the device in the Treeview and update its status
        for item in self.device_tree.get_children():
            if self.device_tree.item(item, "values")[0] == device_id:
                self.device_tree.item(item, values=(device_id, self.devices[device_id].device_type, self.devices[device_id].owner, status))
                break

    def on_device_select(self, event):
        selected_device = self.device_tree.selection()
        if selected_device:
            device_id = self.device_tree.item(selected_device)['values'][0]
            self.device_id_entry.delete(0, tk.END)
            self.device_id_entry.insert(0, device_id)
            self.start_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.NORMAL)

def run_gui():
    root = tk.Tk()
    app = IoTDeviceSimulator(root)
    root.mainloop()

def start_mqtt():
    broker = mqtt.Client()  # Updated Client initialization to avoid DeprecationWarning
    broker.connect(MQTT_BROKER, MQTT_PORT, 60)
    broker.loop_start()

if __name__ == "__main__":
    # Start MQTT broker in a separate thread
    mqtt_thread = threading.Thread(target=start_mqtt)
    mqtt_thread.daemon = True
    mqtt_thread.start()

    # Run GUI in the main thread
    run_gui()
