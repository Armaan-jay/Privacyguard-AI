import pickle, sys

class VerboseUnpickler(pickle.Unpickler):
    def find_class(self, module, name):
        print(f'MODULE={module!r} NAME={name!r}', flush=True)
        return super().find_class(module, name)

with open('ml/malicious_url_model.pkl', 'rb') as f:
    try:
        VerboseUnpickler(f).load()
    except Exception as e:
        print(f'\nFAILED: {e}')
