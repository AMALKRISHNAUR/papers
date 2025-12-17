#!/usr/bin/env python3
"""
Convert trained model to TensorFlow Lite format for TinyML deployment
"""

import numpy as np
import json
import os

try:
    import tensorflow as tf
    HAS_TF = True
except ImportError:
    HAS_TF = False

def convert_to_tflite(keras_model_path, output_path='../model/ids_model.tflite'):
    """
    Convert Keras model to TensorFlow Lite
    """
    if not HAS_TF:
        print("TensorFlow not available for conversion")
        return
    
    # Load model
    model = tf.keras.models.load_model(keras_model_path)
    
    # Convert to TFLite
    converter = tf.lite.TFLiteConverter.from_keras_model(model)
    
    # Enable quantization for smaller model size
    converter.optimizations = [tf.lite.Optimize.DEFAULT]
    
    # For int8 quantization (best for microcontrollers)
    def representative_dataset():
        data = np.load('../dataset/ids_dataset.npz')
        X = data['X_train']
        for i in range(min(100, len(X))):
            yield [X[i:i+1].astype(np.float32)]
    
    converter.representative_dataset = representative_dataset
    converter.target_spec.supported_ops = [tf.lite.OpsSet.TFLITE_BUILTINS_INT8]
    converter.inference_input_type = tf.int8
    converter.inference_output_type = tf.int8
    
    tflite_model = converter.convert()
    
    # Save
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, 'wb') as f:
        f.write(tflite_model)
    
    print(f"TFLite model saved to {output_path}")
    print(f"Model size: {len(tflite_model)} bytes")


def convert_tflite_to_c_array(tflite_path, output_path='../model/ids_model_data.h'):
    """
    Convert TFLite model to C array for embedding
    """
    with open(tflite_path, 'rb') as f:
        model_data = f.read()
    
    with open(output_path, 'w') as f:
        f.write("/*\n")
        f.write(" * TensorFlow Lite Model Data\n")
        f.write(f" * Model size: {len(model_data)} bytes\n")
        f.write(" */\n\n")
        f.write("#ifndef IDS_MODEL_DATA_H_\n")
        f.write("#define IDS_MODEL_DATA_H_\n\n")
        f.write("#include <stdint.h>\n\n")
        f.write(f"const unsigned int ids_model_len = {len(model_data)};\n\n")
        f.write("alignas(8) const unsigned char ids_model_data[] = {\n")
        
        # Write bytes in rows of 12
        for i in range(0, len(model_data), 12):
            chunk = model_data[i:i+12]
            f.write("  " + ", ".join([f"0x{b:02x}" for b in chunk]) + ",\n")
        
        f.write("};\n\n")
        f.write("#endif /* IDS_MODEL_DATA_H_ */\n")
    
    print(f"C array saved to {output_path}")


def generate_simple_c_model(weights_file='../contiki-ng/ids-node/tinyml_model_trained.h'):
    """
    Generate a complete C implementation without TensorFlow
    """
    output = '''/*
 * Simple TinyML Model Implementation for Contiki-NG
 * No external dependencies required
 */

#ifndef TINYML_SIMPLE_MODEL_H_
#define TINYML_SIMPLE_MODEL_H_

#include <stdint.h>

/* Include trained weights */
#include "tinyml_model_trained.h"

/* Model configuration */
#define MODEL_INPUT_SIZE L1_INPUT
#define MODEL_HIDDEN1_SIZE L1_OUTPUT
#define MODEL_HIDDEN2_SIZE L2_OUTPUT
#define MODEL_OUTPUT_SIZE 1

/* Activation functions */
static inline float simple_relu(float x) {
    return x > 0.0f ? x : 0.0f;
}

static inline float simple_sigmoid(float x) {
    /* Fast sigmoid approximation */
    if (x > 5.0f) return 1.0f;
    if (x < -5.0f) return 0.0f;
    
    /* Pade approximation for efficiency */
    float x2 = x * x;
    return (0.5f + x * (0.25f + x2 * 0.0078125f)) / 
           (1.0f + x2 * 0.0625f);
}

/* Forward inference */
static float simple_model_predict(const float* input) {
    float hidden1[MODEL_HIDDEN1_SIZE];
    float hidden2[MODEL_HIDDEN2_SIZE];
    float output;
    int i, j;
    
    /* Layer 1: Input -> Hidden1 */
    for (i = 0; i < MODEL_HIDDEN1_SIZE; i++) {
        hidden1[i] = trained_layer1_bias[i];
        for (j = 0; j < MODEL_INPUT_SIZE; j++) {
            hidden1[i] += input[j] * trained_layer1_weights[j][i];
        }
        hidden1[i] = simple_relu(hidden1[i]);
    }
    
    /* Layer 2: Hidden1 -> Hidden2 */
    for (i = 0; i < MODEL_HIDDEN2_SIZE; i++) {
        hidden2[i] = trained_layer2_bias[i];
        for (j = 0; j < MODEL_HIDDEN1_SIZE; j++) {
            hidden2[i] += hidden1[j] * trained_layer2_weights[j][i];
        }
        hidden2[i] = simple_relu(hidden2[i]);
    }
    
    /* Layer 3: Hidden2 -> Output */
    output = trained_layer3_bias;
    for (i = 0; i < MODEL_HIDDEN2_SIZE; i++) {
        output += hidden2[i] * trained_layer3_weights[i];
    }
    output = simple_sigmoid(output);
    
    return output;
}

/* Initialize model (placeholder for future use) */
static inline void simple_model_init(void) {
    /* Model is statically initialized */
}

/* Get model info */
static inline void simple_model_info(void) {
    /* Can be used for debugging */
}

#endif /* TINYML_SIMPLE_MODEL_H_ */
'''
    
    output_path = '../model/tinyml_simple_model.h'
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    
    with open(output_path, 'w') as f:
        f.write(output)
    
    print(f"Simple C model saved to {output_path}")


if __name__ == "__main__":
    print("TinyML Model Converter")
    print("=" * 40)
    
    # Generate simple C model (always works)
    print("\n[1] Generating simple C model...")
    generate_simple_c_model()
    
    if HAS_TF:
        print("\n[2] Converting to TFLite...")
        try:
            convert_to_tflite('keras_model.h5')
            convert_tflite_to_c_array('../model/ids_model.tflite')
        except Exception as e:
            print(f"TFLite conversion skipped: {e}")
    else:
        print("\n[2] TFLite conversion skipped (TensorFlow not available)")
    
    print("\nConversion complete!")
