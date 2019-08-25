import argparse
import logging
import os
import pickle
import random
import re
import sys
from pathlib import Path

from tqdm import tqdm

# import CuckooAPI
import extract_features
import lief

SECTION_INDEX = 6725

# api = CuckooAPI.CuckooAPI("10.0.0.144", APIPY=True, port=8090)


def parse_args():

    parser = argparse.ArgumentParser(
        description='PE File Feature Extraction. \nThe purpose of this application is extract the feature vectors from PE files for the purpose of malware analysis and malware mutation.')

    parser.add_argument( "malware_file", help="The filepath of the original malicious PE file.",
                        type=Path)
    parser.add_argument(
        '-a', "--adversarial-vector", help="The filepath of the benign PE files whose features are to be extracted.", type=Path, default=Path("adversarial_feature_vector_directory/adversarial_feature_array_set.pk"))
    parser.add_argument(
        '-o',"--output-dir", help="The filepath to where the adversially generated malware will be generated. If this location does not exist, it will be created.", type=Path, default=Path("Mutated Files"))
    parser.add_argument(
        '-f', "--feature-mapping", help="The filepath that stores the feature mappings used.", type=Path, default=Path("feature_vector_directory/feature_vector_mapping.pk"))

    parser.add_argument('-d', "--detailed-log",
                        help="Detailed Logs", type=bool, default=False)
    parser.add_argument('-l', "--logfile", help="The file path to store the logs.",
                        type=str, default="binary_builder_logs.txt")

    help_msg = " ".join(["Set the severity level of logs you want to collect. By default, the logging module logs the messages with a severity level of INFO or above. Valid choices (Enter the numeric values) are: \"[10] - DEBUG\", \"[20] - INFO\",",
                         "\"[30] - WARNING\", \"[40] - ERROR\" and \"[50] - CRITICAL\"."])
    parser.add_argument('-L', "--log-level", help=help_msg,
                        type=int, default=logging.INFO)

    help_msg = " ".join(["Select what features you will be using to reconstruct your malware binary. Valid choices are: \"imports\", \"sections\",",
                         "\"both\"."])
    parser.add_argument('-v', "--feature-vector",
                        help=help_msg, type=str, default="both")

    args = parser.parse_args()
    return args


def logging_setup(detailed_log: bool, logfile: str, log_level: int):

    format_str = '%(name)s - %(asctime)s - %(levelname)s - %(message)s'
    format_date = '%d-%b-%y %H:%M:%S'

    log_dir = "Logs"

    if not os.path.exists(log_dir):
        os.mkdir(log_dir)

    logfile = os.path.join(log_dir, logfile)

    logging.basicConfig(
        level=logging.DEBUG,
        filemode='a',  # other options are w for write.
        datefmt=format_date,
        format=format_str,
        filename=logfile
    )

    if detailed_log:
        handler = logging.StreamHandler(sys.stdout)
        handler.setLevel(logging.DEBUG)
        formatter = logging.Formatter(format_str)
        handler.setFormatter(formatter)
        logging.getLogger().addHandler(handler)
    else:
        handler = logging.StreamHandler(sys.stdout)
        handler.setLevel(log_level)
        formatter = logging.Formatter(format_str)
        handler.setFormatter(formatter)
        logging.getLogger().addHandler(handler)

    logging.info("\n\nStarting Adversial Malware Reconstruction ...")



def imports_to_dict(adversarial_imports_set: list):

    adversarial_imports_dict = {}

    for imports in adversarial_imports_set[0]:
        # print(imports)
        library, function_name = imports.split(':')
        if library not in adversarial_imports_dict:
            adversarial_imports_dict[library] = [function_name]
        else:
            functions = adversarial_imports_dict[library]
            functions.append(function_name)

    logging.debug("The adversarial imports dict : \n" + str(adversarial_imports_dict))

    return adversarial_imports_dict



def binary_builder(malware_pe: str, adversarial_vector: str, feature_mapping: str, output_path: str, feature_type: str):

    section_state = False
    imports_state = False

    lenght_of_features = 0

    RL_features = "RL_Features"

    if not os.path.exists(str(output_path)):
        logging.info("Constructing output directory ...")
        os.makedirs(str(output_path))

    if not os.path.exists(str(RL_features)):
        logging.info("Contruncting RL Features directory ...")
        os.mkdir(str(RL_features))

    logging.info("Constructing features from adversarially generated feature vectors ...")

    if feature_type.lower() == "section":
        
        section_state = True

        output_path = os.path.join(output_path, "Sections")
        if not os.path.exists(str(output_path)):
            logging.info("Constructing output directory for Sections...")
            os.makedirs(str(output_path))
            
        logging.info("Constructing section list ...")
        adversarial_sections_set = section_extractor(
            adversarial_vector, feature_mapping)

        pickle.dump(adversarial_sections_set[0], open(os.path.join(RL_features, "adversarial_sections_set.pk"), 'wb'))

        lenght_of_features = len(adversarial_sections_set)
        logging.info("Section list completed with %d sections ...", len(adversarial_sections_set))
    elif feature_type.lower() == "imports":

        imports_state = True
        adversarial_vector = Path("adversarial_feature_vector_directory\imports_adversarial_feature_array_set.pk")
        feature_mapping = Path("feature_vector_directory\import_feature_vector_mapping.pk")

        output_path = os.path.join(output_path, "Imports")
        if not os.path.exists(str(output_path)):
            logging.info("Constructing output directory for Imports...")
            os.makedirs(str(output_path))

        logging.info("Constructing imports list ...")
        adversarial_imports_set = import_extractor(
            adversarial_vector, feature_mapping)

        pickle.dump(imports_to_dict(adversarial_imports_set), open(os.path.join(RL_features, "adversarial_imports_set.pk"), 'wb'))

        lenght_of_features = len(adversarial_imports_set)
        logging.info("Imports list completed with %d imports ...", len(adversarial_imports_set))
    else:
        imports_state = True
        section_state = True

        output_path = os.path.join(output_path, "features")
        if not os.path.exists(str(output_path)):
            logging.info("Constructing output directory ...")
            os.makedirs(str(output_path))

        logging.info("Constructing section and imports list ...")
        adversarial_imports_set, adversarial_sections_set = features_extractor(
            adversarial_vector, feature_mapping)

        pickle.dump(imports_to_dict(adversarial_imports_set), open(os.path.join(RL_features, "adversarial_imports_set.pk"), 'wb'))
        pickle.dump(adversarial_sections_set[0], open(os.path.join(RL_features, "adversarial_sections_set.pk"), 'wb'))

        lenght_of_features = len(adversarial_imports_set)
        logging.info("Section list completed with %d sections ...", len(adversarial_sections_set))
        logging.info("Imports list completed with %d imports ...", len(adversarial_imports_set))
    

    try:
        logging.info("Generating malware samples ...")
        logging.info("Generating " + str(lenght_of_features) + " mutated malware binaries...")
        # logging.info("Generating 10 mutated malware binaries...")

        # for index in tqdm(range(lenght_of_features), desc="Progress : "):
        for index in tqdm(range(100), desc="Progress : "):                               #For testing purposes. Shift to the above command when done testing.
            #binary = binary_original
            logging.debug("Creating Malware Mutation Number" + str(index))
            binary = lief.parse(str(malware_pe))

            imports_len = 0
            section_len = 0
            adversarial_imports_len = 0
            adversarial_sections_len = 0

            # binary.optional_header.dll_characteristics &= ~lief.PE.DLL_CHARACTERISTICS.DYNAMIC_BASE
            # binary.optional_header.dll_characteristics &= ~lief.PE.DLL_CHARACTERISTICS.NX_COMPAT

            if imports_state:
                imports = [lib.name.lower() + ':' +
                           e.name for lib in binary.imports for e in lib.entries]
                imports = process_imported_functions_output(imports)
                imports_len = len(imports)
                adversarial_imports_len = len(adversarial_imports_set[index])

                logging.debug(
                    "Number of imports in original : " + str(imports_len))
                logging.debug("Number of imports in adversial : " +
                              str(adversarial_imports_len))

                imports_to_be_added = list(
                    set(adversarial_imports_set[index]).difference(set(imports)))
                logging.debug("Number of imports to be added : " +
                              str(len(imports_to_be_added)))

                import_count = 0
                import_threshold = random.randrange(40)

                if len(imports_to_be_added):
                    for lib_func in (imports_to_be_added):

                        if import_count > import_threshold:
                            break

                        library, function_name = lib_func.split(':')
                        logging.debug("import --> " + lib_func)
                        logging.debug("\tlibrary --> " + library)
                        logging.debug("\tFunctionname --> " + function_name)

                        lib = binary.add_library(library)
                        lib.add_entry(function_name)

                else:
                    logging.debug("There are no new imports to be added ...")

            if section_state:
                sections = [section.name for section in binary.sections]
                section_len = len(sections)
                adversarial_sections_len = len(adversarial_sections_set[index])

                logging.debug(
                    "Number of sections in original : " + str(section_len))
                logging.debug("Number of section in adversial : " +
                              str(adversarial_sections_len))

                sections_to_be_added = list(
                    set(adversarial_sections_set[index]).difference(set(sections)))
                logging.debug("Number of sections to be added : " +
                              str(len(sections_to_be_added)))

                section_count = 0
                sections_threshold = random.randrange(60)

                if len(sections_to_be_added):
                    for sec in (sections_to_be_added):

                        if section_count > sections_threshold:
                            break


                        if len(sec) > 6:
                            continue

                        logging.debug("section --> " + sec)
                        new_section = lief.PE.Section(sec)
                        # new_section.content = [0xCC] * 0x1000

                        # fill with random content
                        upper = random.randrange(256)
                        L = random.randrange(100000)
                        new_section.content = [random.randint(0, upper) for _ in range(L)]

                        # new_section.virtual_address = max(
                        #     [s.virtual_address + s.size for s in binary.sections])
                        # add a new empty section

                        binary.add_section(new_section,
                           random.choice([
                               lief.PE.SECTION_TYPES.BSS,
                               lief.PE.SECTION_TYPES.DATA,
                               lief.PE.SECTION_TYPES.EXPORT,
                               lief.PE.SECTION_TYPES.IDATA,
                               lief.PE.SECTION_TYPES.RELOCATION,
                               lief.PE.SECTION_TYPES.RESOURCE,
                               lief.PE.SECTION_TYPES.TEXT,
                               lief.PE.SECTION_TYPES.TLS_,
                               lief.PE.SECTION_TYPES.UNKNOWN,
                           ]))

                        section_count += 1

                else:
                    logging.debug("There are no new imports to be added ...")

            builder = lief.PE.Builder(binary)
            builder.build_dos_stub(False)  # rebuild DOS stub

            builder.build_imports(imports_state)  # rebuild IAT in another section
            # patch original import table with trampolines to new import table
            builder.patch_imports(imports_state)

            builder.build_overlay(False)  # rebuild overlay
            # rebuild relocation table in another section
            builder.build_relocations(False)
            # rebuild resources in another section
            builder.build_resources(False)
            builder.build_tls(False)  # rebuilt TLS object in another section

            logging.debug("Building binary ...")
            builder.build()  # perform the build process

            malware_file = os.path.join(
                output_path, "PE _generated_" + str(index) + ".exe")
            builder.write(malware_file)
            logging.debug("Binary has been generated at : " +
                          str(malware_file))

    except:
        logging.exception(
            "Exception raised at adversial feature no : " + str(index))
        raise Exception("%s is not parseable!" % malware_pe)

    logging.info("Malware samples generation completed ...")
    pass


def import_extractor(adversarial_vector: str, feature_mapping: str):
    logging.info("Loading import feature vector mapping from pickle file ...")
    feature_vector_mapping = pickle.load(open(feature_mapping, 'rb'))
    logging.info(
        "Loading adversarially generated import feature vectors from pickle file ...")
    adversarial_feature_vector = pickle.load(open(adversarial_vector, 'rb'))

    feature_vector_mapping = [
        import_lib for import_lib in feature_vector_mapping]

    logging.debug("adversarial_feature_vector length : %d",
                  len(adversarial_feature_vector))

    adversarial_imports_set = []
    count = 0

    logging.info(
        "Generating imports set from adversarially generated feature vectors ...")
    for index in range(len(adversarial_feature_vector)):
        logging.info("Mapping imports from batch %d  with %d adversarial feature vectors ...", index, len(
            adversarial_feature_vector[index]))
        for i in tqdm(range(len(adversarial_feature_vector[index])), desc="Progress : "):
            sample = adversarial_feature_vector[index][i]
            sample = sample.tolist()
            adversial_imports = []
            unfiltered_adversial_imports =[]

            logging.debug("Sample lenght  : %d", len(sample))

            for i in (range(len(sample))):
                if sample[i] > 0:
                    unfiltered_adversial_imports.append(feature_vector_mapping[i])

            for imports in unfiltered_adversial_imports:
                if "32" in imports:
                    adversial_imports.append(imports)

            adversarial_imports_set.append(adversial_imports)
            logging.debug("Import mapping for adversarial feature vector [" + str(
                count) + "] completed with " + str(len(adversial_imports)) + " imports ...\n")
            count = count + 1

    # logging.info("%d adversarial feature vectors have been mapped ...", count)

    logging.debug("Number of feature vectors : %d",
                  len(adversarial_imports_set))

    return adversarial_imports_set


def section_extractor(adversarial_vector: str, feature_mapping: str):
    logging.info("Loading section feature vector mapping from pickle file ...")
    feature_vector_mapping = pickle.load(open(feature_mapping, 'rb'))
    logging.info(
        "Loading section adversarially generated feature vectors from pickle file ...")
    adversarial_feature_vector = pickle.load(open(adversarial_vector, 'rb'))

    feature_vector_mapping = [
        import_lib for import_lib in feature_vector_mapping]

    logging.debug("adversarial_feature_vector length : %d",
                  len(adversarial_feature_vector))

    adversarial_section_set = []
    count = 0

    logging.info(
        "Generating imports set from adversarially generated feature vectors ...")
    for index in range(len(adversarial_feature_vector)):
        logging.info("Mapping imports from batch %d  with %d adversarial feature vectors ...", index, len(
            adversarial_feature_vector[index]))
        for i in tqdm(range(len(adversarial_feature_vector[index])), desc="Progress : "):
            sample = adversarial_feature_vector[index][i]
            sample = sample.tolist()
            adversial_section = []

            logging.debug("Sample lenght  : %d", len(sample))

            for i in (range(len(sample))):
                if sample[i] > 0:
                    adversial_section.append(feature_vector_mapping[i])

            adversarial_section_set.append(adversial_section)
            logging.debug("Import mapping for adversarial feature vector [" + str(
                count) + "] completed with " + str(len(adversial_section)) + " imports ...\n")
            count = count + 1

    # logging.info("%d adversarial feature vectors have been mapped ...", count)

    logging.debug("Number of feature vectors : %d",
                  len(adversarial_section_set))
    logging.debug("Number of features in the set : %d",
                  len(adversarial_section_set[0]))

    return adversarial_section_set


def features_extractor(adversarial_vector: str, feature_mapping: str):

    logging.info("Loading feature vector mapping from pickle file ...")
    feature_vector_mapping = pickle.load(open(feature_mapping, 'rb'))
    logging.info(
        "Loading adversarially generated feature vectors from pickle file ...")
    adversarial_feature_vector = pickle.load(open(adversarial_vector, 'rb'))

    feature_vector_mapping = [
        import_lib for import_lib in feature_vector_mapping]

    logging.debug("adversarial_feature_vector length : %d",
                  len(adversarial_feature_vector))

    adversarial_imports_set = []
    adversarial_sections_set = []
    count = 0

    logging.info(
        "Generating imports set from adversarially generated feature vectors ...")
    for index in range(len(adversarial_feature_vector)):
        logging.info("Mapping imports from batch %d  with %d adversarial feature vectors ...", index, len(
            adversarial_feature_vector[index]))
        for i in tqdm(range(len(adversarial_feature_vector[index])), desc="Progress : "):
            sample = adversarial_feature_vector[index][i]
            sample = sample.tolist()
            adversial_imports = []
            adversial_section = []
            adversial_features = []

            logging.debug("Sample lenght  : %d", len(sample))
            logging.debug("SECTION INDEX : %d", SECTION_INDEX)

            for i in (range(len(sample))):
                if sample[i] > 0:
                    adversial_features.append(feature_vector_mapping[i])

            for feature in adversial_features:
                if ":" in feature:
                    adversial_imports.append(feature)
                    pass
                else:
                    adversial_section.append(feature)
                    pass

            adversarial_imports_set.append(adversial_imports)
            adversarial_sections_set.append(adversial_section)


            logging.debug("Feature mapping for adversarial feature vector [%d] completed with %d imports and %d sections ...", count, len(
                adversial_imports), len(adversial_section))

            # logging.debug("Import mapping for adversarial feature vector [" + str(count) + "] completed with " + str(len(adversial_imports)) + " imports ...\n")
            count = count + 1

    logging.debug("Number of feature vectors : %d",
                  len(adversarial_imports_set))
    logging.debug("Number of features in the set : %d",
                  len(adversarial_imports_set[0]))

    return adversarial_imports_set, adversarial_sections_set

# From ALFA Adv-mlaware-viz


def filter_imported_functions(func_string_with_library):
    """
    Filters the returned imported functions of binary to remove those with special characters (lots of noise for some reason),
    and require functions to start with a capital letter since Windows API functions seem to obey Upper Camelcase convension.
    """
    func_string = func_string_with_library.split(":")[1]

    if re.match("^[A-Z]{1}[a-zA-Z]*$", func_string):
        return True
    else:
        return False

# From ALFA Adv-mlaware-viz


def remove_encoding_indicator(func_string):
    """
    In many functions there is a following "A" or "W" to indicate unicode or ANSI respectively that we want to remove.
    Make a check that we have a lower case letter
    """
    if (func_string[-1] == 'A' or func_string[-1] == 'W') and func_string[-2].islower():
        return func_string[:-1]
    else:
        return func_string

# From ALFA Adv-mlaware-viz


def process_imported_functions_output(imports):

    imports = list(filter(lambda x: filter_imported_functions(x), imports))
    imports = list(map(lambda x: remove_encoding_indicator(x), imports))

    return imports

def send_to_sandbox(output_dir: str):

    logging.info("Sending files to Cuckoo Box ...")
    mutated_files = os.listdir(output_dir)
    for file in mutated_files:
        logging.debug("Sending %s to Cuckoo Box ...", file)
        api.submitfile(file)

    logging.info("Sendign files to Cuckoo Box complete ...")



def main():
    args = parse_args()

    print(args)

    logging_setup(args.detailed_log, args.logfile, args.log_level)

    if str(args.feature_vector).lower() == "section":
        adversarial_vector = Path("adversarial_feature_vector_directory/sections_adversarial_feature_array_set.pk")
        feature_mapping = Path("feature_vector_directory/section_feature_vector_mapping.pk")
    elif str(args.feature_vector).lower() == "imports":
        adversarial_vector = Path("adversarial_feature_vector_directory\imports_adversarial_feature_array_set.pk")
        feature_mapping = Path("feature_vector_directory\import_feature_vector_mapping.pk")
    else:
        adversarial_vector = str(args.adversarial_vector) 
        feature_mapping = str(args.feature_mapping)

    logging.info("Setting parameters ...")
    logging.info("\tOriginal Malware PE binary - " + str(args.malware_file))
    logging.info("\tAdversarially generated malware Feature Vector - " +
                 str(adversarial_vector))
    logging.info("\tFeature Vector Mapping - " + str(feature_mapping))
    logging.info("\tOutput Directory - " + str(args.output_dir))

    logging.info("\tLogfile - " + str(args.logfile))
    logging.info("\tLog Level - " + str(args.log_level))
    logging.info("\tDetailed Log - " + str(args.detailed_log))
    logging.info("\tFeature vector type - " + str(args.feature_vector))

    binary_builder(str(args.malware_file), str(adversarial_vector),
                   str(feature_mapping), str(args.output_dir), str(args.feature_vector))
    # send_to_sandbox(args.output_dir)
    
    pass


if __name__ == "__main__":
    main()
