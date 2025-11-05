class SeverityClassifier:
    def classify(self, data: dict) -> str:
        """
        Classifies the severity based on input data.

        :param data: Dictionary with keys like 'source', 'path', 'method', etc.
        :return: 'High', 'Medium', or 'Low'
        """
        source = data.get("source", "")
        path = data.get("path", "").lower()

        # Honeypot logic
        if source == "honeypot":
            if any(word in path for word in ['admin', 'root', 'config', 'panel']):
                return 'High'
            if any(word in path for word in ['api', 'login', 'signup']):
                return 'Medium'
            if len(path.split('/')) > 4:
                return 'Medium'
            return 'Low'

        # Rule engine logic
        if source == "rule_engine":
            rule_name = data.get("rule_name", "").lower()
            if "sql" in rule_name or "flood" in rule_name:
                return 'High'
            if "xss" in rule_name:
                return 'Medium'
            return 'Low'

        # Fallback
        return 'Low'
