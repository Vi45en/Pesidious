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
      `pip install https://github.com/lief-project/packages/raw/lief-master-latest/pylief-0.9.0.dev.zip`
 
 
## Running Instructions

### Training Instructions

> :warning: WARNING: This segment is currently under some modification. Please proceed to the next section. 

> Note: If you wish to skip the training and jump directly to testing our trained model [click here](#testing-instructions)

1. Feature extraction and feature mapping vector generation.

   + The first step in the training process is generating a feature vector mapping for section names and import functions from a    malware and benign binary samples.  

   ```sh
   python extract_features.py
   ```
    
   + The `extract_features.py` python script outputs the following files in the output directory:
      + **Features Vector Mapping** - _feature_vector_mapping.pk_, _import_feature_vector_mapping.pk_ and _section_feature_vector_mapping.pk_
      + **Malware Feature Vectors** - _malware-feature-set.pk_, _malware-pe-files-import-feature-set.pk_ and _malware-pe-files-section-feature-set.pk_
      + **Benign Feature Vectors** - _benign-feature-set.pk_, _benign-pe-files-import-feature-set.pk_ and _benign-pe-files-section-feature-set.pk_

1. Malware feature vector mutation using Generative Adversarial Networks. 

   + Once the feature mapping vector and the feature vectors for both the malware and benign binary samples have been generated, we can feed these feature vectors to a MalGAN model to generate adversarial feature vectors which appear to be benign. 
   
   ```sh
   python main_malgan.py Z BATCH_SIZE NUM_EPOCHS MALWARE_FILE BENIGN_FILE 
   ```
   > For more information,[see below.](#acknowledgements)
   
   + Pass either one of the three feature vectors to the `MALWARE_FILE` and `BENIGN_FILE` arguments to generate a feature vector of the respective input.  
   
   >  For example: If you pass `benign-pe-files-import-feature-set.pk` and `malware-pe-files-import-feature-set.pk` as arguments, you will generate an adversarial feature vector `adversarial_feature_array_set.pk` that only contains the imports and not the sections or both.
   
   > CAUTION: Pass feature vectors of the same type as arguments for non-erratic results. 
     
   + The `main_malgan.py` python script outputs the `adversarial_feature_array_set.pk` in the `adversarial_feature_vector_directory` directory.
   
   
1. Binary Imports and Section Reconstruction.

   + Once we have the adversarial feature vector from the MalGAN, we can feed it the `binary_builder.py` python script which uses the original feature mapping vector from step 1 to map the adversarial features back to the import functions and section names. 
   
   ```sh
   python binary_builder.py 
   ```
   
   + Make sure to use the right feature vector mapping for the type of adversarial feature vector you have generated by using the `--feature-vector` optional argument. By default it will use the `feature_vector_mapping.pk` mapping. 
   
   > For example: If you have generated a adversarial feature vector of only the sections, make sure to add the command `--feature-vector section` to correctly reconstruct the section name.
   
   + The `binary_builder.py` python script outputs the `adversarial_imports_set.pk` or the `adversarial_section_set.pk`, based on the feature mapping you select, in the `adversarial_feature_vector_directory` directory. 
   
1. To access the samples that includes unpacked backdoors from VirusTotal, login to the google account ()

### Testing Instructions

The training tests the learning agent after every 550 episodes with 200 samples. If the agent is able to generate 100 (50%) of mutated samples, the training stops and saves the model as dqeaf.pt which is used by the testing script.

1. Create a new directory 'testing-samples' and copy your test samples in it. 

2. python dqeaf-test.py testing-samples

3. The mutated malware samples will be stored in the evaded-samples directory.



## Training and Testing Data

## Testing Procedures and Results

## To Do


## Built With

* [Dropwizard](http://www.dropwizard.io/1.0.2/docs/) - The web framework used
* [Maven](https://maven.apache.org/) - Dependency Management
* [ROME](https://rometools.github.io/rome/) - Used to generate RSS Feeds


## Authors

* **Chandni Vaya** - *Developer Advcocate, IBM & Student, University of Wollongong in Dubai* - [Chandni Vaya](https://github.com/Chandni97)
* **Bedang Sen** - *Developer Advcocate, IBM & Student, University of Wollongong in Dubai* - [Bednag Sen](http://github.com/bedangSen/)
* **Chandni Vaya** - *Developer Advcocate, IBM & Student, University of Wollongong in Dubai* - [Chandni Vaya](https://github.com/Chandni97)
* **Chandni Vaya** - *Developer Advcocate, IBM & Student, University of Wollongong in Dubai* - [Chandni Vaya](https://github.com/Chandni97)

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
