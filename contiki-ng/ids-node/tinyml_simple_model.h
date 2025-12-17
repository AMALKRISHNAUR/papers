/*
 * Simple TinyML Model Implementation for Contiki-NG
 * Uses trained weights from tinyml_model_trained.h
 */

#ifndef TINYML_SIMPLE_MODEL_H_
#define TINYML_SIMPLE_MODEL_H_

#include <stdint.h>
#include "tinyml_model_trained.h"

/* Model configuration from trained weights */
#define MODEL_INPUT_SIZE L1_INPUT
#define MODEL_HIDDEN1_SIZE L1_OUTPUT
#define MODEL_HIDDEN2_SIZE L2_OUTPUT
#define MODEL_OUTPUT_SIZE 1

/* Activation functions */
static inline float simple_relu(float x) {
    return x > 0.0f ? x : 0.0f;
}

static inline float simple_sigmoid(float x) {
    /* Fast sigmoid approximation for embedded systems */
    if (x > 5.0f) return 1.0f;
    if (x < -5.0f) return 0.0f;
    
    /* Taylor series approximation */
    float exp_neg_x = 1.0f - x + (x * x) / 2.0f - (x * x * x) / 6.0f;
    if (exp_neg_x < 0.001f) exp_neg_x = 0.001f;
    return 1.0f / (1.0f + exp_neg_x);
}

/* Forward inference using trained weights */
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

/* Initialize model (placeholder) */
static inline void simple_model_init(void) {
    /* Weights are statically initialized */
}

#endif /* TINYML_SIMPLE_MODEL_H_ */
