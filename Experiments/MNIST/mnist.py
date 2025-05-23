# -*- coding: utf-8 -*-

import flwr as fl
from flwr.common import Metrics
from flwr.common.typing import NDArrays, Scalar
from collections import OrderedDict
from typing import List, Tuple, Dict, Optional
import numpy as np
import tensorflow as tf

from flwr.simulation.ray_transport.utils import enable_tf_gpu_growth

enable_tf_gpu_growth()

"""# Global Constants (Dataset Specific)"""

# global variables
BATCH_SIZE = 64
EPOCH = 60
LEARNING_RATE = 0.001
NORMALIZATION_LAYER = ''
NUM_CLIENTS = 0
EARLY_STOPPING_PATIENCE = 7
DATASET_INPUT_SHAPE = (28 , 28, 1)
IS_IMAGE_DATA = True


# variable arrays for each case
X_trains_fed = np.zeros(1)
Y_trains_fed = np.zeros(1)
X_test_fed = np.zeros(1) # test sets are not actually splitted but we use it as a variable array
Y_test_fed = np.zeros(1)
X_val_fed = np.zeros(1)
Y_val_fed = np.zeros(1)



"""# Dataset Retrieval"""

from tensorflow.keras.utils import to_categorical
from sklearn.model_selection import train_test_split

def load_data():
    (x_train, y_train), (x_test, y_test) = tf.keras.datasets.mnist.load_data()

    x_train = x_train.reshape((60000, 28, 28, 1)).astype('float32')
    x_test = x_test.reshape((10000, 28, 28, 1)).astype('float32')
    
    y_train = to_categorical(y_train, num_classes=10)
    y_test = to_categorical(y_test, num_classes=10)

    # Split train data into training and validation sets
    x_train, x_vals, y_train, y_vals = train_test_split(x_train, y_train, test_size=0.1, random_state=41)

    global X_trains_fed
    global Y_trains_fed
    global X_test_fed
    global Y_test_fed
    global X_val_fed
    global Y_val_fed

    X_trains_fed = np.array(x_train)
    Y_trains_fed = np.array(y_train)
    X_test_fed = np.array(x_test)
    Y_test_fed = np.array(y_test)
    X_val_fed = np.array(x_vals)
    Y_val_fed = np.array(y_vals)

    return


"""# Skew Methods"""

import collections
import numpy as np


def build_ClientData_from_dataidx_map(
        x_train: np.ndarray, y_train: np.ndarray,
        ds_info, dataidx_map, decentralized, display, is_tf):
    """Build dataset for each client based on  dataidx_map

    :param x_train: training split samples
    :param y_train: training split labels
    :param ds_info: dataset information
    :param dataidx_map: distribution of the labels for each client
    :param decentralized: True if running decentralized experiment
    :param display: True if barplot and heatmap are wanted
    :return: dataset for each client based on dataidx_map
    """

    num_clients = ds_info['num_clients']
    num_classes = ds_info['num_classes']
    sample_shape = ds_info['sample_shape']

    numSamplesPerClient = [len(x) for x in dataidx_map.values()]

    sample_height, sample_width, sample_channels = sample_shape

    clientsData = np.zeros(num_clients, dtype=object)
    clientsDataLabels = np.zeros(num_clients, dtype=object)

    for i in range(num_clients):
        clientData = np.zeros(
            (numSamplesPerClient[i], sample_height, sample_width, sample_channels))

        if decentralized:
            clientDataLabels = np.zeros((numSamplesPerClient[i], num_classes))
        else:
            clientDataLabels = np.zeros((numSamplesPerClient[i]))

        for j, s in enumerate(dataidx_map[i]):
            clientData[j] = x_train[s]
            clientDataLabels[j] = y_train[s]

        shuffler = np.random.permutation(len(clientData))
        clientData = clientData[shuffler]
        clientDataLabels = clientDataLabels[shuffler]

        clientsData[i] = clientData
        clientsDataLabels[i] = clientDataLabels


    return clientsData, clientsDataLabels



def iid_distrib(x_train: np.ndarray, y_train: np.ndarray, ds_info,
                decentralized, display=False, is_tf=False):
    """Build an iid distributed dataset for each client

    :param x_train: training split samples
    :param y_train: training split labels
    :param ds_info: dataset information
    :param decentralized: True if running decentralized experiment
    :param display: True if barplot is wanted
    :return: dataset for each client with labels iid distributed
    """

    num_clients = ds_info['num_clients']
    num_classes = ds_info['num_classes']
    sample_shape = ds_info['sample_shape']

    shuffler = np.random.permutation(len(x_train))
    x_train = x_train[shuffler]
    y_train = y_train[shuffler]

    numSamplesPerClient = int(x_train.shape[0] / num_clients)

    sample_height, sample_width, sample_channels = sample_shape

    clientsData = np.zeros((num_clients, int(
        numSamplesPerClient), sample_height, sample_width, sample_channels))

    if decentralized:
        clientsDataLabels = np.zeros(
            (num_clients, int(numSamplesPerClient), num_classes))
    else:
        clientsDataLabels = np.zeros((num_clients, int(numSamplesPerClient)))

    ind = 0
    for i in range(num_clients):
        clientsData[i] = x_train[ind:ind + numSamplesPerClient]
        clientsDataLabels[i] = y_train[ind:ind + numSamplesPerClient]
        ind = ind + numSamplesPerClient


    return clientsData, clientsDataLabels


def qty_skew_distrib(
        x_train: np.ndarray, y_train: np.ndarray, ds_info, beta,
        decentralized, display=False, is_tf=False):
    """Build an quantity-skewed distributed dataset for each client, with Dirichlet distribution
        of parameter beta

    :param x_train: training split samples
    :param y_train: training split labels
    :param ds_info: dataset information
    :param beta: parameter for Dirichlet distribution, greater beta is more balanced dataset
    :param decentralized: True if running decentralized experiment
    :param display: True if barplot and heatmap are wanted
    :return: dataset for each client with a Dir(beta) quantity-skewed distribution
    """

    num_clients = ds_info['num_clients']
    num_classes = ds_info['num_classes']

    idxs = np.random.permutation(y_train.shape[0])
    min_size = 0
    while min_size < num_classes or min_size < BATCH_SIZE:
        proportions = np.random.dirichlet(np.repeat(beta, num_clients))
        proportions = proportions / proportions.sum()
        min_size = np.min(proportions * len(idxs))
    proportions = (np.cumsum(proportions) * len(idxs)).astype(int)[:-1]
    batch_idxs = np.split(idxs, proportions)
    net_dataidx_map = {i: batch_idxs[i] for i in range(num_clients)}

    return build_ClientData_from_dataidx_map(
        x_train, y_train, ds_info, net_dataidx_map,
        decentralized=decentralized, display=display, is_tf=is_tf)


def label_skew_distrib(
        x_train: np.ndarray, y_train: np.ndarray, ds_info, beta,
        decentralized, display=False, is_tf=False):
    """Build an label-skewed distributed dataset for each client, with Dirichlet distribution
        of parameter beta

    :param x_train: training split samples
    :param y_train: training split labels
    :param ds_info: dataset information
    :param beta: parameter for Dirichlet distribution, greater beta is more balanced dataset
    :param decentralized: True if running decentralized experiment
    :param display: True if barplot and heatmap are wanted
    :return: dataset for each client with a Dir(beta) label-skewed distribution
    """

    # https://github.com/Xtra-Computing/NIID-Bench/blob/7a96525cc52dca5bae13266398c123f08b7f833b/utils.py

    num_clients = ds_info['num_clients']
    num_classes = ds_info['num_classes']
    seed = ds_info['seed']

    min_size = 0
    min_require_size = num_classes
    K = num_classes

    if not decentralized:
        y_train_uncat = y_train
    else:
        y_train_uncat = np.array([np.argmax(label_cat)
                                 for label_cat in y_train])

    N = y_train_uncat.shape[0]
    np.random.seed(seed)
    net_dataidx_map = {}

    while min_size < min_require_size or min_size < BATCH_SIZE:
        idx_batch = [[] for _ in range(num_clients)]
        for k in range(K):
            # get indices for class k
            idx_k = np.where(y_train_uncat == k)[0]
            np.random.shuffle(idx_k)
            proportions = np.random.dirichlet(np.repeat(beta, num_clients))

            # Balance
            proportions = np.array([p * (len(idx_j) < N / num_clients)
                                   for p, idx_j in zip(proportions, idx_batch)])

            proportions = proportions / proportions.sum()

            proportions = (np.cumsum(proportions) *
                           len(idx_k)).astype(int)[:-1]

            idx_batch = [idx_j + idx.tolist() for idx_j,
                         idx in zip(idx_batch, np.split(idx_k, proportions))]
            min_size = min([len(idx_j) for idx_j in idx_batch])

    for j in range(num_clients):
        np.random.shuffle(idx_batch[j])
        net_dataidx_map[j] = idx_batch[j]

    return build_ClientData_from_dataidx_map(
        x_train, y_train, ds_info, net_dataidx_map,
        decentralized=decentralized, display=display, is_tf=is_tf
    )


def feature_skew_distrib(
        x_train: np.ndarray, y_train: np.ndarray, ds_info, sigma,
        decentralized, display=False, is_tf=False):
    """Build an feature-skewed distributed dataset for each client, adds a Gaussian noise of parameters N(0,
    (sigma * i/num_clients)**2) for each client i

    :param x_train: training split samples
    :param y_train: training split labels
    :param ds_info: dataset information
    :param sigma: standard deviation for the Gaussian distribution
    :param decentralized: True if running decentralized experiment
    :param display: True if image samples are wanted
    :return: dataset for each client with a Dir(beta) feature-skewed distribution
    """

    num_clients = ds_info['num_clients']
    sample_shape = ds_info['sample_shape']

    sample_height, sample_width, sample_channels = sample_shape

    def noise(sigma_i):
        return np.random.normal(
            scale=sigma_i, size=(sample_height, sample_width, sample_channels)
        )

    clientsData, clientsDataLabels = iid_distrib(
        x_train, y_train, ds_info, decentralized=decentralized, display=display)

    for i in range(num_clients):

        client_ds = clientsData[i]

        client_ds_len = len(client_ds)

        clientData = np.zeros(
            (client_ds_len, sample_height, sample_width, sample_channels))

        for j, sample in enumerate(client_ds):
            # Add gaussian noise to the sample
            clientData[j] = np.maximum([0.0], np.minimum(
                [255.0], sample + noise(sigma * float(i) / float(num_clients-1))))

        clientsData[i] = clientData

    return clientsData, clientsDataLabels

def do_skew(skew_type, num_clients, X_data, Y_data):

    #depends on dataset
    ds_info = { 'num_clients' : num_clients , 'sample_shape' : DATASET_INPUT_SHAPE, 'num_classes':10 , 'seed':12}

    if(skew_type == 'feature_0.01'):
      clientsData, clientsDataLabels = feature_skew_distrib(x_train= X_data, y_train= Y_data, ds_info = ds_info, sigma = 0.01,
            decentralized = True, display=False, is_tf=False)
    elif(skew_type == 'feature_0.1'):
      clientsData, clientsDataLabels = feature_skew_distrib(x_train= X_data, y_train= Y_data, ds_info = ds_info, sigma = 0.1,
            decentralized = True, display=False, is_tf=False)
    elif(skew_type == 'label_5.0'):
      clientsData, clientsDataLabels = label_skew_distrib(x_train= X_data, y_train= Y_data, ds_info = ds_info, beta = 5.0,
            decentralized = True, display=False, is_tf=False)
    elif(skew_type == 'label_0.5'):
      clientsData, clientsDataLabels = label_skew_distrib(x_train= X_data, y_train= Y_data, ds_info = ds_info, beta = 0.5,
        decentralized = True, display=False, is_tf=False)
    elif(skew_type == 'quantity_5.0'):
      clientsData, clientsDataLabels = qty_skew_distrib(x_train= X_data, y_train= Y_data, ds_info = ds_info, beta = 5.0,
            decentralized = True, display=False, is_tf=False)
    elif(skew_type == 'quantity_0.7'):
      clientsData, clientsDataLabels = qty_skew_distrib(x_train= X_data, y_train= Y_data, ds_info = ds_info, beta = 0.7,
            decentralized = True, display=False, is_tf=False)
    elif(skew_type == 'default'):
        clientsData, clientsDataLabels = iid_distrib(x_train= X_data, y_train= Y_data, ds_info = ds_info,
            decentralized = True, display=False)
    else:
        print('error')



    return clientsData, clientsDataLabels

"""# Normalization Methods"""

def merge(data):
  return np.concatenate(data, axis=0)

def split(org_data, merged_array, label_array):
    total_length = sum(arr.shape[0] for arr in org_data)
    ratios = [arr.shape[0] / total_length for arr in org_data]
    split_indices = np.cumsum([int(ratio * merged_array.shape[0]) for ratio in ratios[:-1]])
    split_arrays = np.split(merged_array, split_indices)
    label_split_arrays = np.split(label_array, split_indices)
    return split_arrays, label_split_arrays

def flatten_data(data):
    return data.reshape(data.shape[0],-1)

def flatten_data_for_clients(clientsData):
    flattened_clients_data = [flatten_data(client_data) for client_data in clientsData]
    return flattened_clients_data

def back_to_image(data):
    return data.reshape(data.shape[0], *DATASET_INPUT_SHAPE)

def back_to_image_for_clients(clientsData):
    back_to_image_data = [back_to_image(client_data) for client_data in clientsData]
    return back_to_image_data

from sklearn.preprocessing import StandardScaler
from sklearn.preprocessing import MinMaxScaler
from sklearn.preprocessing import RobustScaler
from sklearn.preprocessing import PowerTransformer

def z_score(train,val,test):
    scaler = StandardScaler()
    scaler.fit(train,None)
    return (scaler.transform(train), scaler.transform(val), scaler.transform(test))

def min_max(train,val,test):
    scaler = MinMaxScaler()
    scaler.fit(train,None)
    return (scaler.transform(train), scaler.transform(val), scaler.transform(test))

def log_scaling(train, val, test):
    return (np.log10(train + 1), np.log10(val + 1), np.log10(test + 1))

def batch_norm():
    global NORMALIZATION_LAYER
    NORMALIZATION_LAYER = 'batch_norm'
    return

def layer_norm():
    global NORMALIZATION_LAYER
    NORMALIZATION_LAYER = 'layer_norm'
    return

def instance_norm():
    global NORMALIZATION_LAYER
    NORMALIZATION_LAYER = 'instance_norm'
    return

def group_norm():
    global NORMALIZATION_LAYER
    NORMALIZATION_LAYER = 'group_norm'
    return

def box_cox(train,val,test):
    transformer = PowerTransformer(method = 'box-cox')
    transformer.fit(train,None)
    return (transformer.transform(train+1), transformer.transform(val+1),transformer.transform(test+1))

def yeo_johnson(train,val,test):
    transformer = PowerTransformer(method = 'yeo-johnson')
    transformer.fit(train,None)
    return (transformer.transform(train), transformer.transform(val),transformer.transform(test))


def robust_scaling(train,val,test, with_centering=True, with_scaling=True, quantile_range=(25.0, 75.0)):
    scaler = RobustScaler(with_centering=with_centering, with_scaling=with_scaling, quantile_range=quantile_range)
    scaler.fit(train,None)
    return (scaler.transform(train), scaler.transform(val),scaler.transform(test))

def do_normalization(normalization_type, num_clients, X_data, val_x, test_x, Y_data, val_y, test_y):


    if(IS_IMAGE_DATA):
        X_data = flatten_data_for_clients(X_data)
        val_x = flatten_data_for_clients(val_x)
        test_x = flatten_data_for_clients(test_x)


    global NORMALIZATION_LAYER

    NORMALIZATION_LAYER = 'default'

    if normalization_type == 'batch_norm':
        NORMALIZATION_LAYER = 'batch_norm'
    elif normalization_type == 'layer_norm':
        NORMALIZATION_LAYER = 'layer_norm'
    elif normalization_type == 'instance_norm':
        NORMALIZATION_LAYER = 'instance_norm'
    elif normalization_type == 'group_norm':
        NORMALIZATION_LAYER = 'group_norm'
    elif normalization_type == 'local_box_cox':
        for i in range(num_clients):
            print(i)
            X_data[i] = box_cox(X_data[i],val_x[i],test_x[i])

    elif normalization_type == 'local_yeo_johnson':
        for i in range(num_clients):
            X_data[i], val_x[i], test_x[i] = yeo_johnson(X_data[i], val_x[i], test_x[i])

    elif normalization_type == 'local_min_max':
        for i in range(num_clients):
            X_data[i], val_x[i], test_x[i] = min_max(X_data[i], val_x[i], test_x[i])

    elif normalization_type == 'local_z_score':
        for i in range(num_clients):
            X_data[i], val_x[i], test_x[i] = z_score(X_data[i], val_x[i], test_x[i])

    elif normalization_type == 'log_scaling':
        for i in range(num_clients):
            X_data[i], val_x[i], test_x[i] = log_scaling(X_data[i], val_x[i], test_x[i])

    elif normalization_type == 'local_robust_scaling':
        for i in range(num_clients):
            X_data[i], val_x[i], test_x[i] = robust_scaling(X_data[i], val_x[i], test_x[i])

    elif normalization_type == 'global_z_score':
        merged_train = merge(X_data)
        merged_val = merge(val_x)
        merged_test = merge(test_x)

        merget_train_y = merge(Y_data)
        merged_val_y = merge(val_y)
        merged_test_y = merge(test_y)

        merged_train, merged_val, merged_test = z_score(merged_train, merged_val, merged_test)

        X_data, Y_data = split(X_data, merged_train, merget_train_y)
        val_x, val_y = split(val_x, merged_val, merged_val_y)
        test_x, test_y = split(test_x, merged_test, merged_test_y)

    elif normalization_type == 'global_min_max':
        merged_train = merge(X_data)
        merged_val = merge(val_x)
        merged_test = merge(test_x)

        merget_train_y = merge(Y_data)
        merged_val_y = merge(val_y)
        merged_test_y = merge(test_y)

        merged_train, merged_val, merged_test = min_max(merged_train, merged_val, merged_test)

        X_data, Y_data = split(X_data, merged_train, merget_train_y)
        val_x, val_y = split(val_x, merged_val, merged_val_y)
        test_x, test_y = split(test_x, merged_test, merged_test_y)

    elif normalization_type == 'global_box_cox':
        merged_train = merge(X_data)
        merged_val = merge(val_x)
        merged_test = merge(test_x)

        merget_train_y = merge(Y_data)
        merged_val_y = merge(val_y)
        merged_test_y = merge(test_y)

        merged_train, merged_val, merged_test = box_cox(merged_train, merged_val, merged_test)

        X_data, Y_data = split(X_data, merged_train, merget_train_y)
        val_x, val_y = split(val_x, merged_val, merged_val_y)
        test_x, test_y = split(test_x, merged_test, merged_test_y)

    elif normalization_type == 'global_robust_scaling':
        merged_train = merge(X_data)
        merged_val = merge(val_x)
        merged_test = merge(test_x)

        merget_train_y = merge(Y_data)
        merged_val_y = merge(val_y)
        merged_test_y = merge(test_y)

        merged_train, merged_val, merged_test = robust_scaling(merged_train, merged_val, merged_test)

        X_data, Y_data = split(X_data, merged_train, merget_train_y)
        val_x, val_y = split(val_x, merged_val, merged_val_y)
        test_x, test_y = split(test_x, merged_test, merged_test_y)

    elif normalization_type == 'global_yeo_johnson':
        merged_train = merge(X_data)
        merged_val = merge(val_x)
        merged_test = merge(test_x)

        merget_train_y = merge(Y_data)
        merged_val_y = merge(val_y)
        merged_test_y = merge(test_y)
        merged_train, merged_val, merged_test = yeo_johnson(merged_train, merged_val, merged_test)

        X_data, Y_data = split(X_data, merged_train, merget_train_y)
        val_x, val_y = split(val_x, merged_val, merged_val_y)
        test_x, test_y = split(test_x, merged_test, merged_test_y)

    elif normalization_type == 'default':
        pass  # default case

    else:
        print("error")


    if(IS_IMAGE_DATA):
        X_data = back_to_image_for_clients(X_data)
        val_x = back_to_image_for_clients(val_x)
        test_x = back_to_image_for_clients(test_x)

    return X_data, val_x, test_x, Y_data, val_y, test_y

"""# Network Model (Dataset Specific)"""

def get_model(kernel_size = (3, 3), dropout = True, pooling = 'max', reg_alpha = 0.001):
    model = tf.keras.Sequential()

    model.add(tf.keras.layers.Conv2D(6, (5, 5), activation='relu', input_shape=DATASET_INPUT_SHAPE))

    if NORMALIZATION_LAYER == 'batch_norm':
        model.add(tf.keras.layers.BatchNormalization())
    elif NORMALIZATION_LAYER == 'instance_norm':
        model.add(tf.keras.layers.GroupNormalization(groups=-1))
    elif NORMALIZATION_LAYER == 'group_norm':
        model.add(tf.keras.layers.GroupNormalization(groups=3))
    elif NORMALIZATION_LAYER == 'layer_norm':
        model.add(tf.keras.layers.LayerNormalization())

    model.add(tf.keras.layers.MaxPooling2D((2, 2)))


    model.add(tf.keras.layers.Conv2D(16, (5, 5), activation='relu'))

    if NORMALIZATION_LAYER == 'batch_norm':
        model.add(tf.keras.layers.BatchNormalization())
    elif NORMALIZATION_LAYER == 'instance_norm':
        model.add(tf.keras.layers.GroupNormalization(groups=-1))
    elif NORMALIZATION_LAYER == 'group_norm':
        model.add(tf.keras.layers.GroupNormalization(groups=4))
    elif NORMALIZATION_LAYER == 'layer_norm':
        model.add(tf.keras.layers.LayerNormalization())

    model.add(tf.keras.layers.MaxPooling2D((2, 2)))


    model.add(tf.keras.layers.Flatten())


    model.add(tf.keras.layers.Dense(units=120, activation='relu'))

    model.add(tf.keras.layers.Dense(units=84, activation='relu'))

    model.add(tf.keras.layers.Dense(10, activation='softmax'))

    return model

"""# Flower Client (Dataset Specific)"""

from flwr.common.typing import NDArrays
class FlowerClient(fl.client.NumPyClient):

    def __init__(self, model: tf.keras.models.Sequential, X_train: np.ndarray, y_train: np.ndarray):
        self.model = model

        self.X_train = X_train
        self.y_train = y_train


    def get_parameters(self, config):
        return self.model.get_weights()


    def fit(self, parameters: NDArrays, config: Dict[str, Scalar]) -> NDArrays:

        self.model.compile(optimizer=tf.keras.optimizers.Adam(learning_rate=LEARNING_RATE), loss='categorical_crossentropy', metrics=['accuracy'])

        self.model.set_weights(parameters)

        history = self.model.fit(self.X_train, self.y_train ,batch_size=BATCH_SIZE, epochs=1, verbose=0)
        results = {
            "loss": history.history["loss"][0],
            "accuracy": history.history["accuracy"][0],
        }
        return self.model.get_weights(), len(self.X_train), results

    def evaluate(self, parameters: NDArrays, config: Dict[str, Scalar])-> Tuple[float, int, Dict[str, Scalar]]:
        self.model.compile(optimizer=tf.keras.optimizers.Adam(learning_rate=LEARNING_RATE), loss='categorical_crossentropy', metrics=['accuracy'])
        self.model.set_weights(parameters)

        loss, acc = self.model.evaluate(self.X_train, self.y_train, verbose=0)
        return loss, len(self.X_train), {"accuracy": acc}

# client creator by client id
def create_client_fn(cid: str) -> FlowerClient:
    model = get_model()
    cid_int = int(cid)
    return FlowerClient(model, X_trains_fed[cid_int], Y_trains_fed[cid_int])

def weighted_average(metrics: List[Tuple[int, Metrics]]) -> Metrics:
    accuracies = [num_examples * m["accuracy"] for num_examples, m in metrics]
    examples = [num_examples for num_examples, _ in metrics]

    # Aggregate and return custom metric (weighted average)
    return {"accuracy": sum(accuracies) / sum(examples)}

from flwr.server import Server
from logging import INFO
from flwr.common.logger import log
from flwr.server.history import History
from flwr.server.strategy import Strategy
from flwr.server.client_manager import ClientManager, SimpleClientManager
import timeit

class CustomFlowerServer(Server):
    def __init__(
        self,
        *,
        client_manager: ClientManager,
        strategy: Optional[Strategy] = None,
    ) -> None:
        super().__init__(client_manager=client_manager, strategy=strategy)


    # Override
    def fit(self, num_rounds: int, timeout: Optional[float]) -> History:
        """Run federated averaging for a number of rounds."""
        history = History()

        # Initialize parameters
        log(INFO, "Initializing global parameters")
        self.parameters = self._get_initial_parameters(timeout=timeout)
        log(INFO, "Evaluating initial parameters")
        res = self.strategy.evaluate(0, parameters=self.parameters)
        if res is not None:
            log(
                INFO,
                "initial parameters (loss, other metrics): %s, %s",
                res[0],
                res[1],
            )
            history.add_loss_centralized(server_round=0, loss=res[0])
            history.add_metrics_centralized(server_round=0, metrics=res[1])

        # Run federated learning for num_rounds
        log(INFO, "FL starting")
        start_time = timeit.default_timer()

        # Early Stopping Parameters
        best_loss = float("inf")
        patience_counter = 0
        minimum_delta = 0.00001  # Example: require at least 0.001 decrease in loss

        for current_round in range(1, num_rounds + 1):
            # Train model and replace previous global model
            res_fit = self.fit_round(
                server_round=current_round,
                timeout=timeout,
            )
            if res_fit is not None:
                parameters_prime, fit_metrics, _ = res_fit  # fit_metrics_aggregated
                if parameters_prime:
                    self.parameters = parameters_prime
                history.add_metrics_distributed_fit(
                    server_round=current_round, metrics=fit_metrics
                )

            # Evaluate model using strategy implementation
            res_cen = self.strategy.evaluate(current_round, parameters=self.parameters)
            if res_cen is not None:
                loss_cen, metrics_cen = res_cen
                log(
                    INFO,
                    "fit progress: (%s, %s, %s, %s)",
                    current_round,
                    loss_cen,
                    metrics_cen,
                    timeit.default_timer() - start_time,
                )
                history.add_loss_centralized(server_round=current_round, loss=loss_cen)
                history.add_metrics_centralized(
                    server_round=current_round, metrics=metrics_cen
                )

            # Evaluate model on a sample of available clients
            res_fed = self.evaluate_round(server_round=current_round, timeout=timeout)
            if res_fed is not None:
                loss_fed, evaluate_metrics_fed, _ = res_fed
                if loss_fed is not None:
                    history.add_loss_distributed(
                        server_round=current_round, loss=loss_fed
                    )
                    history.add_metrics_distributed(
                        server_round=current_round, metrics=evaluate_metrics_fed
                    )

            if res_cen is not None:
                loss_cen, metrics_cen = res_cen

                # Check for improvement
                if loss_cen < best_loss - minimum_delta:
                    best_loss = loss_cen
                    patience_counter = 0  # Reset counter if improvement
                else:
                    patience_counter += 1

                # Early stopping check
                if patience_counter >= EARLY_STOPPING_PATIENCE:
                    log(INFO, "Early stopping triggered at round %s", current_round)
                    break  # Exit the training loop

        # Bookkeeping
        end_time = timeit.default_timer()
        elapsed = end_time - start_time
        log(INFO, "FL finished in %s", elapsed)
        return history

# Required for early stopping
best_accuracy = 0.0
weights = np.array([])
best_loss = float("inf")
minimum_delta = 0.00001  # Example: require at least 0.001 decrease in loss

def evaluate(
    server_round: int,
    parameters: fl.common.NDArrays,
    config: Dict[str, fl.common.Scalar],
    ) -> Optional[Tuple[float, Dict[str, fl.common.Scalar]]]:
    """Centralized evaluation function"""

    model = get_model()
    model.compile(optimizer=tf.keras.optimizers.Adam(learning_rate=LEARNING_RATE), loss='categorical_crossentropy' , metrics=['accuracy'])

    model.set_weights(parameters)

    loss, accuracy = model.evaluate(X_val_fed, Y_val_fed, batch_size=BATCH_SIZE, verbose=0)

    global best_accuracy
    global best_loss
    global weights

    print(f"LOSS: {loss}")
    print(f"BEST_LOSS: {best_loss}")
    print(f"ACCURACY: {accuracy}")
    print(f"BEST_ACCURACY: {best_accuracy}")
    print(f"SERVER_ROUND: {server_round}")

    if loss < best_loss - minimum_delta:
        best_accuracy = accuracy
        weights = parameters
        best_loss = loss

    return loss, {"accuracy": accuracy}

from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, classification_report
def get_results():
    '''
    At the end of the federated learning process, calculates results and returns
    Test F1 Score
    Test Loss
    Test Accuracy
    Test Precision
    Test Recall
    '''
    global X_test_fed, Y_test_fed

    model = get_model()
    model.compile(optimizer=tf.keras.optimizers.Adam(learning_rate=LEARNING_RATE), loss='categorical_crossentropy' , metrics=['accuracy'])
    model.set_weights(weights)

    test_loss, test_accuracy = model.evaluate(X_test_fed, Y_test_fed, batch_size=BATCH_SIZE, verbose=0)

    y_pred_probs = model.predict(X_test_fed)
    y_pred = np.argmax(y_pred_probs, axis=1)  # Convert probabilities to class labels

    # If y_test is one-hot encoded, convert it back to integer labels
    if len(Y_test_fed.shape) > 1:
        Y_test_fed = np.argmax(Y_test_fed, axis=1)

    # Calculate metrics
    accuracy = accuracy_score(Y_test_fed, y_pred)
    precision = precision_score(Y_test_fed, y_pred, average='weighted')
    recall = recall_score(Y_test_fed, y_pred, average='weighted')
    f1 = f1_score(Y_test_fed, y_pred, average='weighted')

    return accuracy, precision, recall, f1, test_loss

def federated_train(x, y, num_clients):

    global X_trains_fed
    global Y_trains_fed
    X_trains_fed = x
    Y_trains_fed = y

    client_resources = {"num_cpus": 2}
    if tf.config.get_visible_devices("GPU"):
        client_resources["num_gpus"] = 0.25

    # Specify the Strategy
    strategy = fl.server.strategy.FedAvg(
        fraction_fit=1.0,  # Sample 100% of available clients for training
        fraction_evaluate=1.0,
        min_fit_clients=num_clients,
        min_evaluate_clients=num_clients,
        min_available_clients=num_clients,  # Wait until all 8 clients are available
        evaluate_metrics_aggregation_fn=weighted_average,
        evaluate_fn=evaluate
    )

    # Start simulation
    history = fl.simulation.start_simulation(
        client_fn=create_client_fn,
        num_clients=num_clients,
        config=fl.server.ServerConfig(num_rounds=EPOCH),
        server=CustomFlowerServer(client_manager=SimpleClientManager(),
        strategy=strategy
        ),
        client_resources=client_resources,
        actor_kwargs={
            "on_actor_init_fn": enable_tf_gpu_growth  # Enable GPU growth upon actor init
            # does nothing if `num_gpus` in client_resources is 0.0
        },
    )

    accuracy, precision, recall, f1, test_loss = get_results()

    return history, accuracy, precision, recall, f1, test_loss

"""# Training and Saving the Results"""

import wandb

wandb.login()


sweep_config = {
    'method': 'grid',
    'name': 'mnist_sweep_1'
    }

metric = {
    'name': 'val_loss',
    'goal': 'minimize'
    }

sweep_config['metric'] = metric

parameters_dict = {
    'b_skew': {
          'values': ['feature_0.1', 'feature_0.01', 'default', 'label_5.0', 'label_0.5', 'quantity_5.0', 'quantity_0.7']
        },
    'a_num_clients': {
          'values': [10, 20, 50]
        },
    'c_normalization': {
          'values': ['local_z_score', 'local_min_max', 'batch_norm', 'layer_norm', 'group_norm', 'instance_norm', 'local_robust_scaling',
                     'global_z_score', 'global_min_max','global_robust_scaling',
                     'default']
        }
    }

sweep_config['parameters'] = parameters_dict

parameters_dict.update({
    'dataset': {
        'value': 'MNIST'},
    'experiment_run': {
        'value': '3'}
    })

sweep_id = wandb.sweep(sweep_config, project="mnist") # to start a new sweep

import time

def train(config = None):
    with wandb.init(config=config, settings=wandb.Settings(_service_wait=300)):
        
        config = wandb.config
        tf.keras.backend.clear_session()

        global NUM_CLIENTS
        global X_test_fed
        global Y_test_fed

        global X_val_fed
        global Y_val_fed


        NUM_CLIENTS = config['a_num_clients']

        load_data()

        clientsData, clientLabels = do_skew(config['b_skew'], config['a_num_clients'], X_trains_fed, Y_trains_fed)
        val_x, val_y = split(clientsData, X_val_fed, Y_val_fed)
        test_x, test_y = split(clientsData, X_test_fed, Y_test_fed)

        #validation and test datasets are normalized with same parameters train dataset is normalized.
        #Data distribution among clients are protected, for local normalization, val and test datasets are normalized with respect to their local train data normalization parameters.
        normalizedData, val_x, test_x, clientLabels, val_y, test_y = do_normalization(config['c_normalization'], config['a_num_clients'], clientsData, val_x, test_x, clientLabels, val_y, test_y)

        X_val_fed = merge(val_x)
        Y_val_fed = merge(val_y)

        X_test_fed = merge(test_x)
        Y_test_fed = merge(test_y)


        t1 = time.perf_counter(), time.process_time()

        history, test_accuracy, test_precision, test_recall, test_f1, test_loss = federated_train(normalizedData, clientLabels, config['a_num_clients'])

        t2 = time.perf_counter(), time.process_time()

        t = t2[1] - t1[1]

        global best_accuracy, weights, best_loss


        if (len(history.losses_centralized) == EPOCH + 1):
            early_stopped_epoch = len(history.losses_centralized) - 1
        else:
            early_stopped_epoch = len(history.losses_centralized) - EARLY_STOPPING_PATIENCE - 1

        # Saving the results
        wandb.log({"time": t})
        wandb.log({"stopped_epoch": early_stopped_epoch})
        wandb.log({"test_accuracy": test_accuracy})
        wandb.log({"test_precision": test_precision})
        wandb.log({"test_recall": test_recall})
        wandb.log({"test_f1": test_f1})
        wandb.log({"test_loss": test_loss})
        wandb.log({"validation_loss": best_loss})
        wandb.log({"validation_accuracy": best_accuracy})


        table = wandb.Table(data=history.losses_distributed, columns=["x", "y"])
        wandb.log(
            {
                "distributed_loss": wandb.plot.line(
                    table, "x", "y", title="Train Set Loss vs Epoch Plot"
                )
            }
        )


        table2 = wandb.Table(data=history.losses_centralized, columns=["x", "y"])
        wandb.log(
            {
                "centralized_loss": wandb.plot.line(
                    table2, "x", "y", title="Validation Set Loss vs Epoch Plot"
                )
            }
        )

        table3 = wandb.Table(data=history.metrics_distributed['accuracy'], columns=["x", "y"])
        wandb.log(
            {
                "distributed_accuracy": wandb.plot.line(
                    table3, "x", "y", title="Train Set Accuracy vs Epoch Plot"
                )
            }
        )

        table4 = wandb.Table(data=history.metrics_centralized['accuracy'], columns=["x", "y"])
        wandb.log(
            {
                "centralized_accuracy": wandb.plot.line(
                    table4, "x", "y", title="Validation Set Accuracy vs Epoch Plot"
                )
            }
        )

        best_accuracy = 0.0
        weights = np.array([])
        best_loss = float("inf")


wandb.agent(sweep_id, train) # to start a new sweep
