import matplotlib.pyplot as plt

def plot_traffic(traffic_data):
    protocols = list(traffic_data.keys())
    counts = list(traffic_data.values())

    plt.figure(figsize=(10, 5))
    plt.bar(protocols, counts, color='blue')
    plt.xlabel('Protocol')
    plt.ylabel('Packet Count')
    plt.title('Network Traffic Analysis')
    plt.show()

if __name__ == "__main__":
    traffic_data = {'TCP': 120, 'UDP': 80, 'HTTP': 50, 'Other': 30}  # Example data
    plot_traffic(traffic_data)