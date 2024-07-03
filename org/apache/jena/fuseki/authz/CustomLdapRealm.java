package org.apache.jena.fuseki.authz;

import java.util.HashSet;
import java.util.Set;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.LdapContext;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.ldap.JndiLdapRealm;
import org.apache.shiro.realm.ldap.LdapContextFactory;
import org.apache.shiro.realm.ldap.LdapUtils;
import org.apache.shiro.subject.PrincipalCollection;

// ... existing imports ...

public class CustomLdapRealm extends JndiLdapRealm {

  private String groupSearchBase;
  private String groupNameAttribute;
  private String memberAttribute;

  @Override
  protected AuthorizationInfo queryForAuthorizationInfo(
    PrincipalCollection principals,
    LdapContextFactory ldapContextFactory
  ) throws NamingException {
    // String username = (String) getAvailablePrincipal(principals);
    String username = (String) principals.getPrimaryPrincipal();
    LdapContext ldapContext = ldapContextFactory.getSystemLdapContext();
    Set<String> roleNames;

    try {
      roleNames = getRoleNamesForUser(username, ldapContext);
    } finally {
      LdapUtils.closeContext(ldapContext);
    }

    return new SimpleAuthorizationInfo(roleNames);
  }

  // Remove @Override annotation if method does not exist in superclass
  protected Set<String> getRoleNamesForUser(
    String username,
    LdapContext ldapContext
  ) throws NamingException {
    SearchControls searchCtls = new SearchControls();
    searchCtls.setSearchScope(SearchControls.SUBTREE_SCOPE);
    String searchFilter =
      "(&(objectClass=groupOfNames)(" +
      memberAttribute +
      "=uid=" +
      username +
      ",ou=agents,dc=hyperdata,dc=it))";

    // Perform LDAP search operation inline
    NamingEnumeration<SearchResult> results = ldapContext.search(
      groupSearchBase,
      searchFilter,
      searchCtls
    );
    Set<String> roleNames = new HashSet<>();
    while (results.hasMore()) {
      SearchResult result = results.next();
      Attribute groupNameAttr = result.getAttributes().get(groupNameAttribute);
      if (groupNameAttr != null) {
        NamingEnumeration<?> groupNames = groupNameAttr.getAll();
        while (groupNames.hasMore()) {
          roleNames.add(groupNames.next().toString());
        }
      }
    }
    return roleNames;
  }

  public void setGroupSearchBase(String groupSearchBase) {
    this.groupSearchBase = groupSearchBase;
  }

  public void setGroupNameAttribute(String groupNameAttribute) {
    this.groupNameAttribute = groupNameAttribute;
  }

  public void setMemberAttribute(String memberAttribute) {
    this.memberAttribute = memberAttribute;
  }
}
