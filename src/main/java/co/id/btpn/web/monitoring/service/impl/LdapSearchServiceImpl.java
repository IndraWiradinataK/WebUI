package co.id.btpn.web.monitoring.service.impl;


import static org.springframework.ldap.query.LdapQueryBuilder.query;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.ldap.core.AttributesMapper;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.ldap.query.LdapQuery;
import org.springframework.ldap.query.SearchScope;
import org.springframework.ldap.support.LdapUtils;
import org.springframework.stereotype.Service;

import co.id.btpn.web.monitoring.service.LdapSearchService;

@Service("ldapSearchService")
public class LdapSearchServiceImpl implements LdapSearchService{

	    private static final Logger logger = LoggerFactory.getLogger(LdapSearchServiceImpl.class);



        private static final Integer THREE_SECONDS = 3000;

        @Autowired
        private LdapTemplate ldapTemplate;
    


        @Override
        public List<Map<String, Object>> getPersonNamesByAccountName(String search) {
                logger.info("SEARCH LDAP NIK >>>>>> {}",search);
                LdapQuery query = query()
                        .searchScope(SearchScope.SUBTREE)
                        .timeLimit(THREE_SECONDS)
                        .base(LdapUtils.emptyLdapName())
                        .countLimit(10)
                        .where("objectClass").is("person")
                        .and("objectClass").is("organizationalPerson")
                 //       .and("uid").like(search)
                        .and("sAMAccountName").like(search)
                ;
                List<Map<String, Object>> searchResult = ldapTemplate.search(query, new MultipleAttributesMapper());
                logger.info("SEARCH RESULT LDAP NIK >>>>>> {}",searchResult);
                return searchResult;
           
        }

   


	private class MultipleAttributesMapper implements AttributesMapper<Map<String, Object>> {

		@Override
		public Map<String, Object>  mapFromAttributes(Attributes attrs) throws NamingException {
			NamingEnumeration<? extends Attribute> all = attrs.getAll();
			
                        Map<String, Object> result = new HashMap<>();
			while (all.hasMore()) {
				Attribute id = all.next();
				result.put(id.getID(),  id.get() );
			}
			
			return result;
		}
	}

    
    
}
