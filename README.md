# Malware Mutation using Deep Reinforcement Learning and GANs 


The purpose of our project is to use artificial intelligence to mutate a malware sample to bypass anti-virus agents while keeping its functionality intact. In the past, notable work has been done in this domain with researchers either looking at reinforcement learning or generative adversarial networks as their weapons of choice to modify the states of a malware executable in order to deceive anti-virus agents. Our solution makes use of a combination of deep reinforcement learning and GANs in order to overcome some of the limitations faced while using these approaches independently.


## Table of Content


+ [Overview](#overview)
+ [Installation Instructions](#installing-instructions)
+ [Running Instructions](#running-instructions)
+ [Training and Testing Data](#training-and-testing-data)
+ [Testing Procedures and results](#testing-procedures-and-results)
+ [Future Additions](#to-do)
+ [Built With](#built-with)
+ [Authors](#authors)
+ [Acknowledgments](#acknowledgements)
+ [References](#references)



## Overview


The proposed solution successfully generates a mutated malware sample by using reinforcement learning to decide on the sequence of modifications to make. In case the modifications chosen by the RL agent is either adding import functions or adding/renaming section names, GANs are used to generate an adversarial feature vector of imports and sections that perturb a malware to appear benign in contrast to randomly selecting the imports and sections. 

<p align="center">
 <img src="https://i.imgur.com/ew95L8R.png" align="middle">
</p>


## Installation Instructions

The following steps will guide you through all the installations required to set up the environment.

1. Install and set up Python 3. [Installation Instructions](https://realpython.com/installing-python/)

1. Clone the repository. 
    ```sh
    git clone https://github.com/hitb-aichallenge/tAIchi.git
    ```
1. Move into the project directory. 

    ```sh
    cd tAIchi
    ```
    
1. Download malware and benign binary samples from [here](#training-and-testing-data).
 
1. Setting up a virtual environment in Python 3.7. 

   1. Downloading and installing _virtualenv_. 
   
   ```sh
   pip install virtualenv
   ```
   
   2. Create the virtual environment in Python 3.7.
   
   ```sh
    virtualenv -p path\to\your\python.exe test_env
    ```    
    >Note: In Windows, your Python3.7 environment is most likely to be in the following directory: `C:\Python37\Python.exe`.
   
   3. Activate the test environment.     
   
        1. For Windows:
        ```sh
        test_env\Scripts\Activate
        ```        
        
        2. For Unix:
        ```sh
        source test_env/bin/activate
        ```    
   4. Test out the version of your virtualenv environment to confirm it is in Python3.7.     
           
   ```sh
   python --version
   ```    

1. Install all the required libraries, by installing the requirements.txt file.

    ```sh
    pip install -r requirements.txt
    ```
    > Refer to the official PyTorch link in order to download the torch library appropriate for you [here](https://pytorch.org/get-started/locally/).
    > Install lief for Python 3.7 using the following command.
      ```sh
      pip install https://github.com/lief-project/packages/raw/lief-master-latest/pylief-0.9.0.dev.zip
      ```

## Running Instructions

### Training Instructions

1. Feature extraction and feature mapping vector generation.

   + The first step in the training process is generating a feature vector mapping for section names and import functions from a    malware and benign binary samples.  

   ```sh
   python extract_features.py
   ```
   
      Command Name                                     | Command                                 | Description
   :---------------------------------------------- | :-------------------------------------- | :----
   Help                                            | `command -h` or `command --help`        | Display the help message and exit.
   Malware Path                                    | `command -m` or `command --malware-path`| The filepath of the malicious PE files whose features are to be extracted. [default = `Data/malware`]
   Benign Path                                     | `command -b` or `command --benign-path` | The filepath of the benign PE files whose features are to be extracted. [default = `Data/benign`]
   Output Directory                                | `command -o` or `command --output-dir`  | The filepath to where the feature vectors will be extracted. If this location does not exist, it will be created. [default = `feature_vector_directory`].
   Detailed Logs                                   | `command -d` or `command --detailed-log`| Display the debug logs on console. [default = `False`].
   Log File                                        | `command -f` or `command --logfile      | The file path to store the logs. [default = `extract_features_logs.txt`.
   Log Level                                       | `command -l` or `command --log-level    | Set the severity level of logs you want to collect. By default, the logging module logs the messages with a severity level of WARNING or above. Valid choices (Enter the numeric values) are: "[10] - DEBUG, [20] - INFO, [30] - WARNING, [40] - ERROR and [50] - CRITICAL. [default = `logging.INFO`].
   
   + The `extract_features.py` python script outputs the following files in the output directory:
      + **Features Vector Mapping** - _feature_vector_mapping.pk_, _import_feature_vector_mapping.pk_ and _section_feature_vector_mapping.pk_
      + **Malware Feature Vectors** - _malware-feature-set.pk_, _malware-pe-files-import-feature-set.pk_ and _malware-pe-files-section-feature-set.pk_
      + **Benign Feature Vectors** - benign-feature-set.pk_, _benign-pe-files-import-feature-set.pk_ and _benign-pe-files-section-feature-set.pk_

1. Malware feature vector mutation using Generative Adversarial Networks. 

   + Once the feature mapping vector and the feature vectors for both the malware and benign binary samples have been generated, we can feed these feature vectors to a MalGAN model to generate adversarial feature vectors which appear to be benign. 
   
   ```sh
   python main_malgan.py Z BATCH_SIZE NUM_EPOCHS MALWARE_FILE BENIGN_FILE 
   ```
   > For more information,[see below.](#acknowledgements)
   
   | Command Name         | Command                          | Description                                                                                                                                                              |
   |----------------------|----------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
   | Help                 | `command -h` or `command --help` | Display the help message and exit.                                                                                                                                       |
   | Z                    |                                  | Dimension of the latent vector.                                                                                                                                          |
   | BATCH_SIZE           |                                  | Batch size.                                                                                                                                                              |
   | NUM_EPOCHS           |                                  | Number of training epochs.                                                                                                                                               |
   | MALWARE_FILE         |                                  | Data file contacting the malware.                                                                                                                                        |
   | BENIGN_FILE          |                                  | Data file contacting the benign.                                                                                                                                         |
   | GEN_HIDDEN_SIZES     | `command --gen-hidden-sizes`     | Dimension of the hidden layer(s) in the GENERATOR.Multiple layers should be space separated. [default: [256, 256]].                                                      |
   | DISCRIM_HIDDEN_SIZES | `command --discrim-hidden-sizes` | Dimension of the hidden layer(s) in the DISCRIMINATOR.Multiple layers should be space separated [default: [256, 256]].                                                   |
   | ACTIVATION           | `command --activation`           | Activation function for the generator and discriminatior hidden layer(s). LeakyReLU).                                                                                    |
   | DETECTOR             | `command --detector              | Learner algorithm used in the black box detector. Valid choices (case insensitive) "DecisionTree", ""MultiLayerPerceptron", "RandomForest", and "(default: RandomForest) |

### Testing Instructions

1. 



## Training and Testing Data

## Testing Procedures and Results

## To Do


## Built With

* [Dropwizard](http://www.dropwizard.io/1.0.2/docs/) - The web framework used
* [Maven](https://maven.apache.org/) - Dependency Management
* [ROME](https://rometools.github.io/rome/) - Used to generate RSS Feeds


## Authors

* **Billie Thompson** - *Initial work* - [PurpleBooth](https://github.com/PurpleBooth)

See also the list of [contributors](https://github.com/your/project/contributors) who participated in this project.

## Acknowledgments

* The gym-malware environment (https://github.com/endgameinc/gym-malware) was modified to extract only 518 out of 2350 features for the training of the agent i.e. byte histogram normalized to sum to unity and two-dimensional entropy histogram. Additionaly only 4 actions are used for the mutation i.e. append random bytes, append import, append section and remove signature.

* Gym-Malware Environment : https://github.com/endgameinc/gym-malware <br>
Deep Reinforcement Learning : https://ieeexplore.ieee.org/stamp/stamp.jsp?arnumber=8676031

* Yanming Lai's ([here])(https://github.com/yanminglai/Malware-GAN) and Zayd Hammoudeh's ([here])(https://github.com/ZaydH/MalwareGAN) work on implementation on Han and Tan's MalGAN played a crucial role in our understanding of the architecture. A mojority of the implementation of the MalGAN used in this project has been forked off Hammoudeh's work. 

## References

Anderson, H., Kharkar, A., Filar, B., Evans, D. and Roth, P. (2018). Learning to Evade Static PE Machine Learning Malware Models via Reinforcement Learning. [online] arXiv.org. Available at: https://arxiv.org/abs/1801.08917.

Docs.microsoft.com. (n.d.). PE Format - Windows applications. [online] Available at: https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#general-concepts.

Fang, Z., Wang, J., Li, B., Wu, S., Zhou, Y. and Huang, H. (2019). Evading Anti-Malware Engines With Deep Reinforcement Learning. [online] Ieeexplore.ieee.org. Available at: https://ieeexplore.ieee.org/abstract/document/8676031 [Accessed 25 Aug. 2019].
https://resources.infosecinstitute.com. (2019). 

Malware Researcher’s Handbook (Demystifying PE File). [online] Available at: https://resources.infosecinstitute.com/2-malware-researchers-handbook-demystifying-pe-file/#gref.

Hu, W. and Tan, Y. (2018). Generating Adversarial Malware Examples for Black-Box Attacks Based on GAN. [online] arXiv.org. Available at: https://arxiv.org/abs/1702.05983.
