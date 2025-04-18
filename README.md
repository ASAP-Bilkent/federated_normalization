# Bridging Local and Federated Data Normalization in Federated Learning: A Privacy-Preserving Approach

This repository contains the codebase and experimental results related to **"Bridging Local and Federated Data Normalization in Federated Learning: A Privacy-Preserving Approach"**.

It is organized into three main directories:

## 📁 Experimental Results

This directory contains the individual results of our experiments. Each `.csv` file contains all runs for a specific dataset.

## 📁 Experiments

This directory includes the code used to run the experiments. Each dataset has its own corresponding runnable `.py` script.  

**Notes:**
- You may need to adjust several variables in the code, such as:
  - Weights & Biases project creation and changing the project name in the code
  - Weights & Biases API login credentials
  - Dataset paths
- Datasets are included in the respective directory. Modify the dataset path accordingly.
- `requirements_image.yml`  and `requirements_tabular.txt` files are provided to set up the Python environments. For MNIST and CIFAR-10 experiments you can use  `requirements_image.yml` and for other datasets you can use `requirements_tabular.txt`. You can create a environments using respectively:

```bash
conda env create -f requirements.yml
```

```bash
pip install -r requirements.txt
```
To run feature imbalanced experiments, you should fill the numerical features arrays in the `skew.py` with the features you want to create imbalance. We have excluded categorical features while doing the experiments.
## 📁 Privacy Implementations

This directory contains proof-of-concept implementations of our proposed privacy-preserving federated normalization techniques. It includes simulations for each normalization technique discussed in the paper.

To run these implementations:

- Make sure you have **Go version 1.21.6** installed.
- Navigate to the directory and run:

```bash
go mod download
```

to install the required Go modules.
