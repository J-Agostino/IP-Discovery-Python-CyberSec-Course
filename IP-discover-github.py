import netifaces
import nmap
import requests
import json

# Prompt the user to select a network interface
interfaces = netifaces.interfaces()
print("Interfaces disponibles en tu equipo:\n")
for i, iface in enumerate(interfaces):
    print(f"{i + 1}. {iface}")
selection = int(input("\nElegi tu interfaz (numero): ")) - 1
interface = interfaces[selection]

# Get the IP address of the selected network interface
ip_address = netifaces.ifaddresses(interface)[netifaces.AF_INET][0]['addr']
print("Para la interfaz", interface,"la IP es",ip_address)

nm = nmap.PortScanner()
ip_list = []

ip_network = nm.scan(hosts='192.168.1.0/24', arguments='-sn')
print("\nDirecciones IP encontradas:")
print('--------------')
for ip in ip_network['scan'].keys():
    ip_list.append(ip)
    print(ip)

print('--------------')

confirm = input('\nNmap va a usar las direcciones anteriores para ser escaneadas, quieres continuar? s/n: ')
if confirm == 's':
    print('Esto puede tomar un tiempo. Recomiendo tener un mate listo para cebar mientras esperas.\n')
else:
    print('Okay, entonces hasta aqui llego el programa.\nAdios!')
    exit()

# Scan the host for open TCP and UDP ports
results = {}

for i in ip_list:    
    try:
        nm.scan(hosts=i, arguments="-F -sS -sU --script=banner")
        tcp_open = nm[i]['tcp'].keys()
        udp_open = nm[i]['udp'].keys()

        tcp_results = []
        for port in tcp_open:
            port_data = {
                "port": port,
                "product": nm[i]['tcp'][port]['product'],
                "version": nm[i]['tcp'][port]['version'],
                "name": nm[i]['tcp'][port]['name']
            }
            tcp_results.append(port_data)

        udp_results = []
        for port in udp_open:
            port_data = {
                "port": port,
                "product": nm[i]['udp'][port]['product'],
                "version": nm[i]['udp'][port]['version'],
                "name": nm[i]['udp'][port]['name']
            }
            udp_results.append(port_data)

        results[i] = {"tcp": tcp_results, "udp": udp_results}

        if len(tcp_open) > 0:
            print(f"Puertos TCP abiertos en {i}:")
            for port in tcp_open:
                print(f"\tPuerto {port}: {nm[i]['tcp'][port]['product']} {nm[i]['tcp'][port]['version']} ({nm[i]['tcp'][port]['name']})")
        else:
            print(f"Ningun puerto TCP abierto/encontrado en {i}")

        if len(udp_open) > 0:
            print(f"Puertos UDP abiertos en {i}:")
            for port in udp_open:
                print(f"\tPuerto {port}: {nm[i]['udp'][port]['product']} {nm[i]['udp'][port]['version']} ({nm[i]['udp'][port]['name']})")
        else:
            print(f"Ningun puerto UDP abierto/encontrado en {i}")
    except KeyError:
        print(f"Ningun puerto abierto/encontrado en  {i}")

# save results to JSON file
with open('scan_results.json', 'w') as outfile:
    json.dump(results, outfile)

# make POST request to URL
try:
    url = "http://127.0.0.1/example/fake_url.php"
    headers = {'Content-type': 'application/json'}
    response = requests.post(url, json=results, headers=headers)
    response.raise_for_status()
    print("\nEl resultado fue exportado a la URL")
except requests.exceptions.RequestException as e:
    print(f"\nError: No hay conexion con la URL - {e}")
