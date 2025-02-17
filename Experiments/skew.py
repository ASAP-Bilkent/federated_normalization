import numpy as np
import matplotlib.pyplot as plt
from sklearn.preprocessing import LabelEncoder
from collections import defaultdict
import numpy as np
import pandas as pd

NUMERICAL_FEATURES = [] #depending on dataset. used for feature skew. to exclude categorical features

def qty_skew_dist(X_train, y_train, num_clients, beta=0.5, batch_size=1):
    clientsData = []
    clientsDataLabel = []
    indices = np.arange(len(X_train))
    np.random.shuffle(indices)

    # Ensure each client receives at least one sample
    min_samples_per_client = 1
    if batch_size > 1:
        min_samples_per_client = batch_size

    initial_samples = num_clients * min_samples_per_client
    if initial_samples > len(X_train):
        raise ValueError("Not enough samples to distribute the minimum required per client. Increase data size or reduce number of clients.")

    start = 0
    for i in range(num_clients):
        end = start + min_samples_per_client
        client_indices = indices[start:end]
        clientsData.append(X_train[client_indices])
        clientsDataLabel.append(y_train[client_indices])
        start = end

    remaining_samples = len(X_train) - initial_samples
    remaining_indices = indices[initial_samples:] 

    if remaining_samples > 0:
        # Calculate proportions for the remaining samples using Dirichlet distribution
        proportions = np.random.dirichlet(np.ones(num_clients) * beta, size=1)[0]
        proportions = np.round(proportions * remaining_samples).astype(int)
        proportions[-1] = remaining_samples - np.sum(proportions[:-1])

        start = 0
        for i in range(num_clients):
            end = start + proportions[i]
            client_indices = remaining_indices[start:end]
            clientsData[i] = np.concatenate((clientsData[i], X_train[client_indices]))
            clientsDataLabel[i] = np.concatenate((clientsDataLabel[i], y_train[client_indices]))
            start = end

    return clientsData, clientsDataLabel


def label_skew_dist(X_train, y_train, num_clients, num_classes, beta=5, batch_size=1):
    clientsData = []
    clientsDataLabel = []

    class_indices = {i: np.where(y_train == i)[0] for i in range(num_classes)}

    label_proportions = np.random.dirichlet(np.ones(num_classes) * beta, size=num_clients)
    
    total_samples_per_client = np.round(label_proportions * len(y_train)).astype(int).sum(axis=1)
    total_samples_per_client = np.maximum(total_samples_per_client, batch_size * np.ones(num_clients).astype(int))

    while np.sum(total_samples_per_client) > len(y_train):
        total_samples_per_client[np.argmax(total_samples_per_client)] -= 1

    shuffled_indices = np.random.permutation(len(y_train))

    start_idx = 0
    for i in range(num_clients):
        end_idx = start_idx + total_samples_per_client[i]
        client_indices = shuffled_indices[start_idx:end_idx]
        start_idx = end_idx

        clientsData.append(X_train[client_indices])
        clientsDataLabel.append(y_train[client_indices])

    return clientsData, clientsDataLabel


def feature_skew_dist(X_train, y_train, num_clients, sigma=0.5, batch_size=1):
    """
    Add Gaussian noise to numerical features in the dataset. Also splits the data to clients.
    """
    clientsData = []
    clientsDataLabel = []
    num_samples = X_train.shape[0]
    
    indices = np.random.permutation(num_samples)
    X_train = X_train[indices]
    y_train = y_train[indices]

    # Get column indices for numerical features
    df = pd.read_csv("{data_path}")
    num_feature_indices = [df.columns.get_loc(col) - 1 for col in NUMERICAL_FEATURES]  # -1 to adjust for label removal

    samples_per_client = max(batch_size, num_samples // num_clients)
    
    for i in range(num_clients):
        start_idx = i * samples_per_client
        end_idx = min(start_idx + samples_per_client, num_samples)

        client_X = X_train[start_idx:end_idx].copy() 
        client_y = y_train[start_idx:end_idx]

        # Generate Gaussian noise for numerical features
        noise = np.zeros_like(client_X)
        noise[:, num_feature_indices] = np.random.normal(
            0, sigma * (i / num_clients), size=(client_X.shape[0], len(num_feature_indices))
        )

        client_X += noise  

        clientsData.append(client_X)
        clientsDataLabel.append(client_y)

    return clientsData, clientsDataLabel

def iid_dist(X_train, y_train, num_clients, batch_size=1):
    """Distribute data equally to a number of clients in an IID manner."""
    clientsData = []
    clientsDataLabel = []
    indices = np.arange(len(X_train))
    np.random.shuffle(indices)
    
    samples_per_client = max(batch_size, len(indices) // num_clients)
    remainder = len(indices) % num_clients

    start = 0
    for i in range(num_clients):
        if i < remainder:
            end = start + samples_per_client + 1
        else:
            end = start + samples_per_client
        
        client_indices = indices[start:end]
        clientsData.append(X_train[client_indices])
        clientsDataLabel.append(y_train[client_indices])
        start = end

    return clientsData, clientsDataLabel

def plot_class_distribution_per_client(clientsDataLabel, class_labels, title):
    """Plot the distribution of classes for each client."""
    num_clients = len(clientsDataLabel)
    num_classes = len(class_labels)
    class_counts = np.zeros((num_clients, num_classes + 1))

    for i, labels in enumerate(clientsDataLabel):
        for j, label in enumerate(class_labels):
            class_counts[i, j] = np.sum(labels == label)
        class_counts[i, -1] = np.sum(class_counts[i, :-1])

    fig, ax = plt.subplots(figsize=(12, 6))
    im = ax.imshow(class_counts, cmap='Blues', aspect='auto')

    ax.set_xticks(np.arange(num_classes + 1))
    ax.set_yticks(np.arange(num_clients))
    xlabels = class_labels + ["Total"]
    ax.set_xticklabels(xlabels)
    ax.set_yticklabels([f'Client {i+1}' for i in range(num_clients)])

    plt.setp(ax.get_xticklabels(), rotation=45, ha="right", rotation_mode="anchor")

    for i in range(num_clients):
        for j in range(num_classes + 1): 
            count = int(class_counts[i, j])
            ax.text(j, i, count, ha="center", va="center", color="black" if count > class_counts.max()/2 else "white")

    ax.set_title(title)
    plt.xlabel('Class Label')
    plt.ylabel('Client')
    plt.colorbar(im)
    plt.tight_layout()
    plt.show()

def plot_feature_skew(X_train, clientsData, num_features_to_plot=3, num_clients_to_plot=3):
    num_clients = len(clientsData)
    num_features = X_train.shape[1]
    print(num_clients,num_features)

    features_to_plot = np.random.choice(range(num_features), size=min(num_features_to_plot, num_features), replace=False)
    clients_to_plot = np.random.choice(range(num_clients), size=min(num_clients_to_plot, num_clients), replace=False)

    fig, axes = plt.subplots(len(clients_to_plot), len(features_to_plot), figsize=(12, 8))
    for i, client_idx in enumerate(clients_to_plot):
        for j, feature_idx in enumerate(features_to_plot):
            ax = axes[i, j]
            original_feature = X_train[:, feature_idx]
            skewed_feature = clientsData[client_idx][:, feature_idx]
            ax.scatter(original_feature, skewed_feature, alpha=0.5)
            ax.set_xlabel('Original Feature')
            ax.set_ylabel('Skewed Feature')
            ax.set_title(f'Client {client_idx + 1}, Feature {feature_idx + 1}')
    plt.tight_layout()
    plt.show()