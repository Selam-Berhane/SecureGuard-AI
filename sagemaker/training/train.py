import argparse
import os
import json
import pandas as pd
import xgboost as xgb
from sklearn.metrics import (
    accuracy_score, 
    precision_score, 
    recall_score, 
    f1_score,
    roc_auc_score,
    confusion_matrix
)


def parse_args():
    """Parse command line arguments from SageMaker"""
    parser = argparse.ArgumentParser()
    
    # Hyperparameters (passed from deploy_model.py)
    parser.add_argument('--max_depth', type=int, default=6)
    parser.add_argument('--eta', type=float, default=0.3)
    parser.add_argument('--gamma', type=float, default=0)
    parser.add_argument('--min_child_weight', type=int, default=1)
    parser.add_argument('--subsample', type=float, default=0.8)
    parser.add_argument('--colsample_bytree', type=float, default=0.8)
    parser.add_argument('--objective', type=str, default='binary:logistic')
    parser.add_argument('--num_round', type=int, default=100)
    parser.add_argument('--eval_metric', type=str, default='auc')

    # SageMaker directories (set by SageMaker automatically)
    parser.add_argument('--model-dir', type=str, default=os.environ.get('SM_MODEL_DIR'))
    parser.add_argument('--train', type=str, default=os.environ.get('SM_CHANNEL_TRAIN'))
    parser.add_argument('--validation', type=str, default=os.environ.get('SM_CHANNEL_VALIDATION'))
    parser.add_argument('--output-data-dir', type=str, default=os.environ.get('SM_OUTPUT_DATA_DIR'))
    
    return parser.parse_args()

def load_data(train_path , val_path):
    """ Load training and validation datasets"""
    train_df = pd.read_csv(os.path.join(train_path, 'training_data.csv'))
    val_df = pd.read_csv(os.path.join(val_path,"validation_data.csv"))

    feature_columns = [col for col in train_df.columns if col not in ['finding_id', 'type', 'severity', 'label']]
    X_train = train_df[feature_columns].values
    Y_train = train_df['label'].values
    X_val = val_df[feature_columns].values
    Y_val = val_df['label'].values

    return X_train, Y_train, X_val, Y_val, feature_columns

def train_model(X_train, Y_train, X_val, Y_val, feature_columns, args):
    print("Training XGBoost Model")
    dtrain = xgb.DMatrix(X_train, label= Y_train, feature_names=feature_columns)
    dval = xgb.DMatrix(X_val, label=Y_val, feature_names= feature_columns)
    #set Hyper-parameters
    params = {
        'max_depth': args.max_depth,
        'eta': args.eta,
        'gamma': args.gamma,
        'min_child_weight': args.min_child_weight,
        'subsample': args.subsample,
        'colsample_bytree': args.colsample_bytree,
        'objective': args.objective,
        'eval_metric': args.eval_metric,
        'seed': 42
    }

    evals = [(dtrain, 'train'), (dval, 'validation')]
    evals_result = {}

    model = xgb.train(
        params= params,
        dtrain = dtrain,
        num_boost_round = args.num_round,
        evals= evals,
        evals_result = evals_result,
        early_stopping_rounds = 10,
        verbose_eval =10
    )

    best_iteration = model.best_iteration
    print(f"best iteration: {best_iteration}")

    return model, evals_result


def evaluate_model(model, X, y, feature_colums, dataset_name="Dataset"):
    dmatrix = xgb.DMatrix(X, feature_names=feature_colums)
    y_pred_proba = model.predict(dmatrix)
    y_pred = (y_pred_proba >0.5).astype(int)

    metrics = {
        'accuracy': float(accuracy_score(y, y_pred)),
        'precision': float(precision_score(y, y_pred, zero_division=0)),
        'recall': float(recall_score(y, y_pred, zero_division=0)),
        'f1': float(f1_score(y, y_pred, zero_division=0)),
        'auc': float(roc_auc_score(y, y_pred_proba))
    }

    print(f"  Accuracy:  {metrics['accuracy']:.4f}")
    print(f"  Precision: {metrics['precision']:.4f}")
    print(f"  Recall:    {metrics['recall']:.4f}")
    print(f"  F1 Score:  {metrics['f1']:.4f}")
    print(f"  AUC:       {metrics['auc']:.4f}")

    cm = confusion_matrix(y, y_pred)

    return metrics, cm

def save_model(model, feature_columns, train_metrics, val_metrics, evals_result, args):
    model_path = os.path.join(args.model_dir, 'xgboost-model')
    model.save_model(model_path)
    print(f"✓ Model saved: {model_path}")
    
    # Save feature names
    feature_names_path = os.path.join(args.model_dir, 'feature_names.json')
    with open(feature_names_path, 'w') as f:
        json.dump(feature_columns, f)
    print(f"✓ Feature names saved: {feature_names_path}")
    
    # Save model metadata
    metadata = {
        'model_type': 'xgboost',
        'version': '1.0',
        'num_features': len(feature_columns),
        'feature_names': feature_columns,
        'hyperparameters': {
            'max_depth': args.max_depth,
            'eta': args.eta,
            'gamma': args.gamma,
            'min_child_weight': args.min_child_weight,
            'subsample': args.subsample,
            'colsample_bytree': args.colsample_bytree,
            'objective': args.objective,
            'num_round': args.num_round
        },
        'best_iteration': int(model.best_iteration),
        'metrics': {
            'train': train_metrics,
            'validation': val_metrics
        }
    }
    
    metadata_path = os.path.join(args.model_dir, 'model_metadata.json')
    with open(metadata_path, 'w') as f:
        json.dump(metadata, f, indent=2)
    print(f"✓ Metadata saved: {metadata_path}")
    

    
    importance = model.get_score(importance_type='gain')
    importance_sorted = sorted(importance.items(), key=lambda x: x[1], reverse=True)
    
    for feature, score in importance_sorted[:10]:
        print(f"  {feature:30s}: {score:8.2f}")
    
    # Save evaluation results
    if args.output_data_dir:
        eval_results_path = os.path.join(args.output_data_dir, 'evaluation_results.json')
        with open(eval_results_path, 'w') as f:
            json.dump({
                'evals_result': evals_result,
                'train_metrics': train_metrics,
                'val_metrics': val_metrics
            }, f, indent=2)
        print(f"\n Evaluation results saved: {eval_results_path}")



def main():
    args = parse_args()
    #load data
    X_train, y_train, X_val, y_val, feature_columns = load_data(args.train, args.validation)
    #train model
    model, evals_result = train_model(X_train, y_train, X_val, y_val, feature_columns, args)
    #evaluate
    train_metrics, _ = evaluate_model(model, X_train, y_train, feature_columns, "Training")
    val_metrics, _ = evaluate_model(model, X_val, y_val, feature_columns, "Validation")
    #save model
    save_model(model, feature_columns, train_metrics, val_metrics, evals_result, args)


# INFERENCE FUNCTIONS (for SageMaker endpoint serving)

def model_fn(model_dir):
    """
    Load the XGBoost model from the model directory.
    This function is called once when the endpoint starts.
    """
    import xgboost as xgb
    import json
    model_path = os.path.join(model_dir, 'xgboost-model')
    model = xgb.Booster()
    model.load_model(model_path)

    # Load feature names if available
    feature_names_path = os.path.join(model_dir, 'feature_names.json')
    if os.path.exists(feature_names_path):
        with open(feature_names_path, 'r') as f:
            feature_names = json.load(f)
    else:
        feature_names = None

    return {'model': model, 'feature_names': feature_names}


def input_fn(request_body, content_type='application/json'):
    """
    Deserialize and prepare the input data for prediction.
    """
    import json
    import numpy as np
    if content_type == 'application/json':
        data = json.loads(request_body)

        # Handle both single prediction and batch predictions
        if 'features' in data:
            features = data['features']
            if not isinstance(features[0], list):
                # Single prediction - wrap in list
                features = [features]
        else:
            raise ValueError("Input must contain 'features' key")

        return np.array(features, dtype=np.float32)
    else:
        raise ValueError(f"Unsupported content type: {content_type}")


def predict_fn(input_data, model_dict):
    """
    Make predictions using the loaded model.
    """
    import xgboost as xgb
    model = model_dict['model']
    feature_names = model_dict['feature_names']

    # Create DMatrix for prediction
    dmatrix = xgb.DMatrix(input_data, feature_names=feature_names)

    # Get predictions
    predictions = model.predict(dmatrix)

    return predictions


def output_fn(predictions, accept='application/json'):
    """
    Serialize the prediction output.
    """
    import json
    if accept == 'application/json':
        # Convert predictions to threat scores and confidence
        results = []
        for pred in predictions:
            threat_score = float(pred * 100)  # Convert 0-1 probability to 0-100 score
            confidence = float(abs(pred - 0.5) * 2)  # Distance from 0.5, scaled to 0-1
            prediction_class = int(pred >= 0.5)

            results.append({
                'threat_score': threat_score,
                'confidence': confidence,
                'prediction': prediction_class
            })

        # Return single result if only one prediction
        if len(results) == 1:
            return json.dumps(results[0])
        else:
            return json.dumps(results)
    else:
        raise ValueError(f"Unsupported accept type: {accept}")



if __name__ == '__main__':
    main()