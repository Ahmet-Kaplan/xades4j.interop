/*
 * XAdES4j - A Java library for generation and verification of XAdES signatures.
 * Copyright (C) 2014 Luis Goncalves.
 *
 * XAdES4j is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or any later version.
 *
 * XAdES4j is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more
 * details.
 *
 * You should have received a copy of the GNU Lesser General Public License along
 * with XAdES4j. If not, see <http://www.gnu.org/licenses/>.
 */
package xades4j.interop.verification;

import java.io.File;
import java.io.FileFilter;
import java.security.KeyStore;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.CollectionCertStoreParameters;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedList;
import java.util.List;
import java.util.UUID;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;
import org.apache.xml.security.utils.Constants;
import static org.junit.Assert.*;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;
import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import xades4j.providers.CertificateValidationProvider;
import xades4j.providers.impl.PKIXCertificateValidationProvider;
import xades4j.verification.XAdESVerificationResult;
import xades4j.verification.XadesVerificationProfile;
import xades4j.verification.XadesVerifier;

/**
 *
 * @author Luís
 */
@RunWith(Parameterized.class)
public class SignatureVerficationTest 
{      
    @Parameters(name = "{0}")
    public static Iterable<Object[]> data() throws Exception 
    {
        // Each directory under 'verificationBundlesDir' contains a set of signatures
        // and the corresponding verification data (certificates and crls). See
        // the README on 'verificationBundlesDir'.
        
        File verificationBundlesDir = new File("src/test/resources/verification");
        File[] testBundles = verificationBundlesDir.listFiles(new FileFilter() {
            public boolean accept(File pathname) {
                return pathname.isDirectory() && !pathname.getName().startsWith("_");
            }
        });
        
        List<Object[]> params = new LinkedList<Object[]>();
        for (File dir : testBundles) 
        {
            Iterable<SignatureVerificationTestCase> testCases = SignatureVerificationTestCase.loadFrom(dir);
            for (SignatureVerificationTestCase tc : testCases) 
            {
                params.add(new Object[]{ tc });    
            }
        }
        
        return params;
    }

    SignatureVerificationTestCase testCase;
    
    public SignatureVerficationTest(SignatureVerificationTestCase testCase) 
    {
        this.testCase = testCase;
    }

    @Test
    public void test() throws Exception
    {
        KeyStore trustAnchors = KeyStore.getInstance("jks");
        trustAnchors.load(null);
        for (Certificate cert : testCase.trustAnchors) {
            trustAnchors.setCertificateEntry(UUID.randomUUID().toString(), cert);
        }
        
        Collection validationData = new ArrayList();
        validationData.addAll(testCase.certificates);
        validationData.addAll(testCase.crls);
        CertStore validationDataStore = CertStore.getInstance("Collection", new CollectionCertStoreParameters(validationData)); 
        
        CertificateValidationProvider v = new PKIXCertificateValidationProvider(
                trustAnchors,
                !testCase.crls.isEmpty(), // Enable revocation if we have CRLs
                validationDataStore);
        XadesVerificationProfile p = new XadesVerificationProfile(v);
        XadesVerifier verifier = p.newVerifier();
        
        setXmlIds(testCase.signatureDocument);
        Element sigElem = (Element)testCase.signatureDocument.getElementsByTagNameNS(Constants.SignatureSpecNS, Constants._TAG_SIGNATURE).item(0);
        
        XAdESVerificationResult res = verifier.verify(sigElem, null);

        if(testCase.expectedForm != null)
        {        
            assertEquals(testCase.expectedForm, res.getSignatureForm());
        }
    }

    private static final XPathExpression selectAllElementswithIdAttr;
    
    static
    {
        try {
            XPath xPath =  XPathFactory.newInstance().newXPath();
            selectAllElementswithIdAttr = xPath.compile("//*[@Id | @id]");
        } catch (XPathExpressionException ex) {
            throw new RuntimeException(ex);
        }
    }
    
    private static void setXmlIds(Document d) throws XPathExpressionException 
    {
        // For each element in the document, if it has an "Id" or "id" attribute,
        // use it as XML ID.
        
        NodeList elementsWithId = (NodeList)selectAllElementswithIdAttr.evaluate(d, XPathConstants.NODESET);
        for (int i = 0; i < elementsWithId.getLength(); i++)
        {
            Element elem = (Element)elementsWithId.item(i);
            Attr idAttr = elem.getAttributeNode(Constants._ATT_ID);
            if(idAttr == null)
            {
                idAttr = elem.getAttributeNode(Constants._ATT_ID.toLowerCase());
            }
            
            elem.setIdAttributeNode(idAttr, true);
        }
    }
}
