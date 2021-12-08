package co.id.btpn.web.monitoring.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import co.id.btpn.web.monitoring.model.Userapp;

import java.util.List;


/**
 *
 * @author Ferry Fadly
 */
@Repository("userappRepository")
public interface UserappRepository extends JpaRepository<Userapp, Long> {

    @Query("SELECT r FROM Userapp r where r.name  = :name ") 
    List<Userapp> findByName(@Param("name") String name);
	 
}
