# Re-export base classes at plugin package level for cleaner imports
from cipherrescue.plugins import Action, AuthToken, PluginError, SchemePlugin

__all__ = ["SchemePlugin", "AuthToken", "Action", "PluginError"]
