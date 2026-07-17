from app.schemas.user import UserCreate
from app.schemas.user_profile import UserProfileCreate, UserProfileUpdate
from app.services.user_profile_service import UserProfileService
from app.services.user_service import UserService


def test_create_user_profile(db_session):
    service = UserProfileService(db_session)

    profile = service.create_user_profile(
        UserProfileCreate(
            name="Operators",
            permissions={
                "acc_view": True,
                "acc_edit": True,
                "mgm_profiles": True,
            },
        )
    )

    assert profile["id"] is not None
    assert profile["name"] == "Operators"
    assert profile["permissions"].acc_view is True
    assert profile["permissions"].mgm_profiles is True


def test_update_user_profile(db_session):
    service = UserProfileService(db_session)
    profile = service.create_user_profile(UserProfileCreate(name="Support"))

    updated = service.update_user_profile(
        profile["id"],
        UserProfileUpdate(name="Support Team", permissions={"acc_view": True, "acc_view_pass": True}),
    )

    assert updated is not None
    assert updated["name"] == "Support Team"
    assert updated["permissions"].acc_view_pass is True


def test_create_user_assigns_profile(db_session):
    profile_service = UserProfileService(db_session)
    profile = profile_service.create_user_profile(UserProfileCreate(name="Assigned Profile"))

    user_service = UserService(db_session)
    user = user_service.create_user(
        UserCreate(
            username="profileuser",
            email="profile@example.com",
            password="password123",
            user_profile_id=profile["id"],
         user_group_id=1)
    )

    assert user.userProfileId == profile["id"]
    response = user_service.to_response(user)
    assert response["user_profile_id"] == profile["id"]


def test_user_profile_routes_are_registered():
    from app.main import app

    route_paths = [route.path for route in app.routes]

    assert "/api/v1/user-profiles" in route_paths
    assert "/api/v1/user-profiles/{profile_id}" in route_paths
