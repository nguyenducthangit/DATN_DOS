import os
import pickle
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.ensemble import RandomForestClassifier
from includes import *

def create_and_save_model():
    """
    Tạo và lưu model đơn giản để phát hiện tấn công
    """
    print("Creating and saving attack detection model...")
    
    # Load training data
    if os.path.isfile('training_data.pkl'):
        train_df = pd.read_pickle('training_data.pkl')
        print("Training data loaded from pickle file.")
    else:
        print("Error: training_data.pkl not found.")
        return None, None, None
    
    # Create and fit the scaler
    scaler = StandardScaler()
    scaler.fit(train_df[X_columns])
    print("Scaler created and fitted.")
    
    # Create a simple model (Random Forest for demonstration)
    # In practice, you would use the actual trained federated learning model
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    
    # Train the model
    print("Training model...")
    model.fit(train_df[X_columns], train_df[y_column])
    print("Model training completed.")
    
    # Create output directory
    output_dir = "PKL"
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    # Save the model
    model_path = os.path.join("models", "model_rf.pkl")
    with open(model_path, 'wb') as f:
        pickle.dump(model, f)
    print(f"Model saved to: {model_path}")
    
    # Save the scaler
    scaler_path = os.path.join("models", "scaler.pkl")
    with open(scaler_path, 'wb') as f:
        pickle.dump(scaler, f)
    print(f"Scaler saved to: {scaler_path}")
    
    # Save model metadata
    metadata = {
        'model_type': 'RandomForest',
        'num_classes': len(train_df[y_column].unique()),
        'feature_columns': X_columns,
        'label_column': y_column,
        'class_mappings': {
            'dict_2_classes': dict_2_classes,
            'dict_8_classes': dict_8_classes,
            'dict_34_classes': dict_34_classes
        }
    }
    
    metadata_path = os.path.join(output_dir, "model_metadata.pkl")
    with open(metadata_path, 'wb') as f:
        pickle.dump(metadata, f)
    print(f"Model metadata saved to: {metadata_path}")
    
    # Tạo và fit label encoder
    le = LabelEncoder()
    le.fit(train_df[y_column])

    # Lưu label encoder
    encoder_path = os.path.join("models", "label_encoder.pkl")
    with open(encoder_path, 'wb') as f:
        pickle.dump(le, f)
    print(f"Label encoder saved to: {encoder_path}")
    
    print(f"\nModel saved successfully!")
    print(f"Model files saved in: {os.path.abspath(output_dir)}")
    print("You can now use simple_attack_detector.py to detect attacks!")
    
    return model_path, scaler_path, metadata_path

def main():
    """
    Main function
    """
    print("=== Simple Model Saver ===")
    print("This script creates a simple model for attack detection")
    print("Note: This is a demonstration model. For production, use the actual federated learning model.\n")
    
    model_path, scaler_path, metadata_path = create_and_save_model()
    
    if model_path:
        print("\n=== Model Creation Complete ===")
        print(f"Model: {model_path}")
        print(f"Scaler: {scaler_path}")
        print(f"Metadata: {metadata_path}")
        print("\nYou can now use simple_attack_detector.py to detect attacks!")
    else:
        print("Model creation failed.")

if __name__ == "__main__":
    main() 