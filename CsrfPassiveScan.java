package org.zaproxy.zap.extension.pscanrules;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.SortedSet;
import java.util.TreeSet;
import net.htmlparser.jericho.Attribute;
import net.htmlparser.jericho.Element;
import net.htmlparser.jericho.HTMLElementName;
import net.htmlparser.jericho.Source;
import org.apache.commons.lang.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Plugin.AlertThreshold;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.zap.extension.anticsrf.ExtensionAntiCSRF;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;
import org.zaproxy.zap.extension.ruleconfig.RuleConfigParam;
import org.zaproxy.zap.model.Vulnerabilities;
import org.zaproxy.zap.model.Vulnerability;


public class CsrfCountermeasuresScanRule extends PluginPassiveScanner {

    
    private static Vulnerability vuln = Vulnerabilities.getVulnerability("wasc_9");

    private static final Map<String, String> ALERT_TAGS =
            CommonAlertTag.toMap(
                    CommonAlertTag.OWASP_2021_A01_BROKEN_AC,
                    CommonAlertTag.OWASP_2017_A05_BROKEN_AC,
                    CommonAlertTag.WSTG_V42_SESS_05_CSRF);

    private ExtensionAntiCSRF extensionAntiCSRF;
    private String csrfIgnoreList;
    private String csrfAttIgnoreList;
    private String csrfValIgnoreList;

    /** the logger */
    private static Logger logger = LogManager.getLogger(CsrfCountermeasuresScanRule.class);

 
    @Override
    public int getPluginId() {
        return 10202;
    }

    /**
     * scans each form in the HTTP response for known anti-CSRF tokens. If any form exists that does
     * not contain a known anti-CSRF token, raise an alert.
     */
    @Override
    public void scanHttpResponseReceive(HttpMessage msg, int id, Source source) {
        if (AlertThreshold.HIGH.equals(getAlertThreshold()) && !msg.isInScope()) {
            return; // At HIGH threshold return if the msg isn't in scope
        }

       
        source.fullSequentialParse();

        long start = System.currentTimeMillis();

        ExtensionAntiCSRF extAntiCSRF = getExtensionAntiCSRF();

        if (extAntiCSRF == null) {
            return;
        }

        List<Element> formElements = source.getAllElements(HTMLElementName.FORM);
        List<String> tokenNames = extAntiCSRF.getAntiCsrfTokenNames();

        if (formElements != null && formElements.size() > 0) {
            boolean hasSecurityAnnotation = false;

            // Loop through all of the FORM tags
            logger.debug("Found {} forms", formElements.size());

            int numberOfFormsPassed = 0;

            List<String> ignoreList = new ArrayList<>();
            String ignoreConf = getCSRFIgnoreList();
            if (ignoreConf != null && ignoreConf.length() > 0) {
                logger.debug("Using ignore list: {}", ignoreConf);
                for (String str : ignoreConf.split(",")) {
                    String strTrim = str.trim();
                    if (strTrim.length() > 0) {
                        ignoreList.add(strTrim);
                    }
                }
            }
            String ignoreAttName = getCSRFIgnoreAttName();
            String ignoreAttValue = getCSRFIgnoreAttValue();

            for (Element formElement : formElements) {
                logger.debug(
                        "FORM [{}] has parent [{}]", formElement, formElement.getParentElement());
                StringBuilder sbForm = new StringBuilder();
                SortedSet<String> elementNames = new TreeSet<>(String.CASE_INSENSITIVE_ORDER);
                ++numberOfFormsPassed;
                if (formElement.getParentElement() == null) {
                    logger.debug(
                            "Skipping HTML form because it has no parent. Likely not actually HTML.");
                    continue; 
                }
                if (formOnIgnoreList(formElement, ignoreList)) {
                    continue;
                }
                if (!StringUtils.isEmpty(ignoreAttName)) {
                    Attribute att = formElement.getAttributes().get(ignoreAttName);
                    if (att != null) {
                        if (StringUtils.isEmpty(ignoreAttValue)
                                || ignoreAttValue.equals(att.getValue())) {
                            hasSecurityAnnotation = true;
                        }
                    }
                }

                List<Element> inputElements = formElement.getAllElements(HTMLElementName.INPUT);
                sbForm.append("[Form " + numberOfFormsPassed + ": \"");
                boolean foundCsrfToken = false;

                if (inputElements != null && inputElements.size() > 0) {
                    logger.debug("Found {} inputs", inputElements.size());
                    for (Element inputElement : inputElements) {
                        String attId = inputElement.getAttributeValue("ID");
                        if (attId != null) {
                            elementNames.add(attId);
                            for (String tokenName : tokenNames) {
                                if (attId.toLowerCase().contains(tokenName.toLowerCase())) {
                                    foundCsrfToken = true;
                                    break;
                                }
                            }
                        }
                        String name = inputElement.getAttributeValue("NAME");
                       
                        if (name != null) {
                            if (attId == null) {
                                elementNames.add(name);
                            }
                            for (String tokenName : tokenNames) {
                                
                                if (name.toLowerCase().contains(tokenName.toLowerCase())) {
                                    foundCsrfToken = true;
                                    break;
                                }
                            }
                        }
                    }
                }
                if (foundCsrfToken) {
                    continue;
                }

                String evidence = "";
                evidence = formElement.getFirstElement().getStartTag().toString();
                
                sbForm.append(String.join("\" \"", elementNames));
                sbForm.append("\" ]");

                String formDetails = sbForm.toString();
                String tokenNamesFlattened = tokenNames.toString();

                int risk = Alert.RISK_MEDIUM;
                String desc = Constant.messages.getString("pscanrules.noanticsrftokens.desc");
                String extraInfo =
                        Constant.messages.getString(
                                "pscanrules.noanticsrftokens.alert.extrainfo",
                                tokenNamesFlattened,
                                formDetails);
                if (hasSecurityAnnotation) {
                    risk = Alert.RISK_INFO;
                    extraInfo =
                            Constant.messages.getString(
                                    "pscanrules.noanticsrftokens.extrainfo.annotation");
                }

                newAlert()
                        .setRisk(risk)
                        .setConfidence(Alert.CONFIDENCE_LOW)
                        .setDescription(desc + "\n" + getDescription())
                        .setOtherInfo(extraInfo)
                        .setSolution(getSolution())
                        .setReference(getReference())
                        .setEvidence(evidence)
                        .setCweId(getCweId())
                        .setWascId(getWascId())
                        .raise();
            }
        }
        logger.debug("\tScan of record {} took {} ms", id, System.currentTimeMillis() - start);
    }

    private boolean formOnIgnoreList(Element formElement, List<String> ignoreList) {
        String id = formElement.getAttributeValue("id");
        String name = formElement.getAttributeValue("name");
        for (String ignore : ignoreList) {
            if (ignore.equals(id)) {
                logger.debug("Ignoring form with id = {}", id);
                return true;
            } else if (ignore.equals(name)) {
                logger.debug("Ignoring form with name = {}", name);
                return true;
            }
        }
        return false;
    }

    @Override
    public String getName() {
        return Constant.messages.getString("pscanrules.noanticsrftokens.name");
    }

    public String getDescription() {
        if (vuln != null) {
            return vuln.getDescription();
        }
        return "Failed to load vulnerability description from file";
    }

    public String getSolution() {
        if (vuln != null) {
            return vuln.getSolution();
        }
        return "Failed to load vulnerability solution from file";
    }

    public String getReference() {
        if (vuln != null) {
            StringBuilder sb = new StringBuilder();
            for (String ref : vuln.getReferences()) {
                if (sb.length() > 0) {
                    sb.append('\n');
                }
                sb.append(ref);
            }
            return sb.toString();
        }
        return "Failed to load vulnerability reference from file";
    }

    @Override
    public Map<String, String> getAlertTags() {
        return ALERT_TAGS;
    }

    public int getCweId() {
        return 352; 
    }

    public int getWascId() {
        return 9;
    }

    protected ExtensionAntiCSRF getExtensionAntiCSRF() {
        if (extensionAntiCSRF == null) {
            return Control.getSingleton()
                    .getExtensionLoader()
                    .getExtension(ExtensionAntiCSRF.class);
        }
        return extensionAntiCSRF;
    }

    protected void setExtensionAntiCSRF(ExtensionAntiCSRF extensionAntiCSRF) {
        this.extensionAntiCSRF = extensionAntiCSRF;
    }

    protected String getCSRFIgnoreList() {
        if (csrfIgnoreList == null) {
            return Model.getSingleton()
                    .getOptionsParam()
                    .getConfig()
                    .getString(RuleConfigParam.RULE_CSRF_IGNORE_LIST);
        }
        return csrfIgnoreList;
    }

    protected void setCsrfIgnoreList(String csrfIgnoreList) {
        this.csrfIgnoreList = csrfIgnoreList;
    }

    protected String getCSRFIgnoreAttName() {
        if (csrfAttIgnoreList == null) {
            return Model.getSingleton()
                    .getOptionsParam()
                    .getConfig()
                    .getString(RuleConfigParam.RULE_CSRF_IGNORE_ATT_NAME, null);
        }
        return csrfAttIgnoreList;
    }

    protected void setCSRFIgnoreAttName(String csrfAttIgnoreList) {
        this.csrfAttIgnoreList = csrfAttIgnoreList;
    }

    protected String getCSRFIgnoreAttValue() {
        if (csrfValIgnoreList == null) {
            return Model.getSingleton()
                    .getOptionsParam()
                    .getConfig()
                    .getString(RuleConfigParam.RULE_CSRF_IGNORE_ATT_VALUE, null);
        }
        return csrfValIgnoreList;
    }

    protected void setCSRFIgnoreAttValue(String csrfValIgnoreList) {
        this.csrfValIgnoreList = csrfValIgnoreList;
    }
}
