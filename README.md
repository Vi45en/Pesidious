# dqeaf-gym-malware 

A malware mutation agent trained using deep reinforcement learning

Overview
======
The agent uses neural networks to mutate the malware by take the malware features as input and getting the action to perform as output. 


Setup
======

The project built on Python3.6 we recommend first creating a virtualenv (details can be found [here]) with Python3.6 then performing the following actions ensure you have the correct python libraries:

[here]: https://docs.python.org/3/tutorial/venv.html
```sh
pip install -r requirements.txt
```
It also uses LIEF to parse and modify malware. 

[LIEF]: https://github.com/lief-project/LIEF

Linux
```
pip install https://github.com/lief-project/LIEF/releases/download/0.7.0/linux_lief-0.7.0_py3.6.tar.gz
```

OSX
```
pip install https://github.com/lief-project/LIEF/releases/download/0.7.0/osx_lief-0.7.0_py3.6.tar.gz
```

Gym-Malware Environment
====

The gym-malware environment (https://github.com/endgameinc/gym-malware) was modified to extract only 518 out of 2350 features for the training of the agent i.e. byte histogram normalized to sum to unity and two-dimensional entropy histogram. Additionaly only 4 actions are used for the mutation i.e. append random bytes, append import, append section and remove signature.


Resources
======

Gym-Malware Environment : https://github.com/endgameinc/gym-malware
Deep Reinforcement Learning : https://ieeexplore.ieee.org/stamp/stamp.jsp?arnumber=8676031
